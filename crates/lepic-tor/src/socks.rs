//! SOCKS5 to an onion through tor: the domain address type, so tor resolves the name and no
//! DNS query leaves the computer, and username/password credentials, so each send gets its own
//! circuit under `IsolateSOCKSAuth`. Tor's extended replies (`ExtendedErrors`) say why an onion
//! could not be reached.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const VERSION: u8 = 5;
const METHOD_USERNAME_PASSWORD: u8 = 2;
const AUTH_VERSION: u8 = 1;
const COMMAND_CONNECT: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;
const CREDENTIAL_BYTES: usize = 16;

/// How long reaching an onion may take: a first circuit to a fresh onion often needs most of a
/// minute. The GUI wallet waits 72 s; tor itself gives up on an onion that is not there only
/// after two minutes, too long for a person to wait.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(75);

/// A failure reply from the SOCKS server, standard or tor's extended ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SocksReply {
    GeneralFailure,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    /// `0xF0`: tor found no descriptor for the onion.
    OnionNotFound,
    /// `0xF1`
    OnionDescriptorInvalid,
    /// `0xF2`: every introduction point failed.
    OnionIntroductionFailed,
    /// `0xF3`
    OnionRendezvousFailed,
    /// `0xF4`: the onion needs client authorization.
    OnionMissingClientAuth,
    /// `0xF5`
    OnionWrongClientAuth,
    /// `0xF6`: the address is not a valid onion.
    OnionAddressInvalid,
    /// `0xF7`
    OnionIntroductionTimedOut,
    Other(u8),
}

impl SocksReply {
    /// The failure a reply code stands for; `None` for success (`0x00`).
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x00 => return None,
            0x01 => Self::GeneralFailure,
            0x02 => Self::NotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TtlExpired,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::AddressTypeNotSupported,
            0xF0 => Self::OnionNotFound,
            0xF1 => Self::OnionDescriptorInvalid,
            0xF2 => Self::OnionIntroductionFailed,
            0xF3 => Self::OnionRendezvousFailed,
            0xF4 => Self::OnionMissingClientAuth,
            0xF5 => Self::OnionWrongClientAuth,
            0xF6 => Self::OnionAddressInvalid,
            0xF7 => Self::OnionIntroductionTimedOut,
            other => Self::Other(other),
        })
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
            Self::OnionNotFound => 0xF0,
            Self::OnionDescriptorInvalid => 0xF1,
            Self::OnionIntroductionFailed => 0xF2,
            Self::OnionRendezvousFailed => 0xF3,
            Self::OnionMissingClientAuth => 0xF4,
            Self::OnionWrongClientAuth => 0xF5,
            Self::OnionAddressInvalid => 0xF6,
            Self::OnionIntroductionTimedOut => 0xF7,
            Self::Other(code) => code,
        }
    }

    /// What the reply means for the person sending, as the GUI groups it.
    pub const fn class(self) -> SendFailure {
        match self {
            Self::OnionNotFound
            | Self::OnionIntroductionFailed
            | Self::OnionIntroductionTimedOut
            | Self::HostUnreachable
            | Self::ConnectionRefused => SendFailure::Unreachable,
            Self::OnionAddressInvalid => SendFailure::InvalidAddress,
            Self::OnionMissingClientAuth | Self::OnionWrongClientAuth => SendFailure::ClientAuth,
            _ => SendFailure::Broken,
        }
    }
}

/// A send over Tor that failed, grouped by what the person can do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SendFailure {
    /// The wallet's tor is not running or not bootstrapped.
    TorOff,
    /// The recipient's wallet is not online with Tor on, or could not be reached in time.
    Unreachable,
    /// Not a valid onion address.
    InvalidAddress,
    /// The connection dropped or tor failed in another way; trying again may work.
    Broken,
    /// The onion needs a client key this wallet does not have.
    ClientAuth,
    /// Something answered, but not an Epic wallet's foreign API.
    NotEpic,
    /// The recipient's wallet is too old to receive this way.
    TooOld,
    /// The recipient's wallet refused the slate.
    Refused,
}

/// Why the SOCKS connection failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SocksError {
    #[error("could not reach the socks proxy")]
    ProxyUnreachable(#[source] std::io::Error),
    #[error("the connection was not made in time")]
    Timeout,
    #[error("the socks connection failed")]
    Io(#[source] std::io::Error),
    #[error("the socks proxy answered outside the protocol")]
    Protocol,
    #[error("the socks proxy refused the credentials")]
    AuthRefused,
    #[error("the socks proxy could not connect: {0:?}")]
    Refused(SocksReply),
    #[error("the host name is too long for socks")]
    HostTooLong,
    #[error("the system random generator failed")]
    Randomness(#[source] getrandom::Error),
}

impl SocksError {
    pub const fn class(&self) -> SendFailure {
        match self {
            Self::ProxyUnreachable(_) => SendFailure::TorOff,
            Self::Timeout => SendFailure::Unreachable,
            Self::Refused(reply) => reply.class(),
            Self::HostTooLong => SendFailure::InvalidAddress,
            Self::Io(_) | Self::Protocol | Self::AuthRefused | Self::Randomness(_) => {
                SendFailure::Broken
            }
        }
    }
}

/// Username and password for one send. Tor checks neither; it only keeps streams with
/// different credentials on different circuits.
#[derive(Clone, PartialEq, Eq)]
pub struct SocksCredentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for SocksCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocksCredentials([redacted])")
    }
}

impl SocksCredentials {
    /// Fresh random credentials, so this send shares no circuit with any other.
    pub fn random() -> Result<Self, SocksError> {
        Ok(Self {
            username: random_hex()?,
            password: random_hex()?,
        })
    }
}

fn random_hex() -> Result<String, SocksError> {
    let mut bytes = [0u8; CREDENTIAL_BYTES];
    getrandom::fill(&mut bytes).map_err(SocksError::Randomness)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The greeting: version 5, one method, username/password.
pub const fn encode_greeting() -> [u8; 3] {
    [VERSION, 1, METHOD_USERNAME_PASSWORD]
}

/// Checks the server's method choice.
pub fn parse_method_reply(reply: [u8; 2]) -> Result<(), SocksError> {
    match reply {
        [VERSION, METHOD_USERNAME_PASSWORD] => Ok(()),
        [VERSION, _] => Err(SocksError::AuthRefused),
        _ => Err(SocksError::Protocol),
    }
}

/// The RFC 1929 username/password request.
pub fn encode_auth(credentials: &SocksCredentials) -> Result<Vec<u8>, SocksError> {
    let user = u8::try_from(credentials.username.len()).map_err(|_| SocksError::Protocol)?;
    let pass = u8::try_from(credentials.password.len()).map_err(|_| SocksError::Protocol)?;
    let mut out = vec![AUTH_VERSION, user];
    out.extend_from_slice(credentials.username.as_bytes());
    out.push(pass);
    out.extend_from_slice(credentials.password.as_bytes());
    Ok(out)
}

pub fn parse_auth_reply(reply: [u8; 2]) -> Result<(), SocksError> {
    match reply {
        [AUTH_VERSION, 0] => Ok(()),
        [AUTH_VERSION, _] => Err(SocksError::AuthRefused),
        _ => Err(SocksError::Protocol),
    }
}

/// `CONNECT` to `host:port` with the domain address type.
pub fn encode_connect(host: &str, port: u16) -> Result<Vec<u8>, SocksError> {
    let length = u8::try_from(host.len()).map_err(|_| SocksError::HostTooLong)?;
    if length == 0 {
        return Err(SocksError::HostTooLong);
    }
    let mut out = vec![VERSION, COMMAND_CONNECT, 0, ADDRESS_DOMAIN, length];
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// The bound address that follows a reply's first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundAddress {
    /// This many bytes, the port included.
    Fixed(usize),
    /// A length byte, then that many bytes and the port.
    Domain,
}

/// Reads the first four bytes of the `CONNECT` reply.
pub fn parse_connect_head(head: [u8; 4]) -> Result<BoundAddress, SocksError> {
    let [version, code, _reserved, address_type] = head;
    if version != VERSION {
        return Err(SocksError::Protocol);
    }
    if let Some(reply) = SocksReply::from_code(code) {
        return Err(SocksError::Refused(reply));
    }
    match address_type {
        ADDRESS_IPV4 => Ok(BoundAddress::Fixed(4 + 2)),
        ADDRESS_IPV6 => Ok(BoundAddress::Fixed(16 + 2)),
        ADDRESS_DOMAIN => Ok(BoundAddress::Domain),
        _ => Err(SocksError::Protocol),
    }
}

/// Connects through the SOCKS5 proxy at `proxy` to `host:port`, all within `wait`.
pub async fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    credentials: &SocksCredentials,
    wait: Duration,
) -> Result<TcpStream, SocksError> {
    let connect_request = encode_connect(host, port)?;
    let auth_request = encode_auth(credentials)?;
    tokio::time::timeout(wait, async {
        let mut stream = TcpStream::connect(proxy)
            .await
            .map_err(SocksError::ProxyUnreachable)?;
        stream.set_nodelay(true).map_err(SocksError::Io)?;
        handshake(&mut stream, &auth_request, &connect_request).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| SocksError::Timeout)?
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth_request: &[u8],
    connect_request: &[u8],
) -> Result<(), SocksError> {
    stream
        .write_all(&encode_greeting())
        .await
        .map_err(SocksError::Io)?;
    parse_method_reply(read_array(stream).await?)?;
    stream
        .write_all(auth_request)
        .await
        .map_err(SocksError::Io)?;
    parse_auth_reply(read_array(stream).await?)?;
    stream
        .write_all(connect_request)
        .await
        .map_err(SocksError::Io)?;
    let remaining = match parse_connect_head(read_array(stream).await?)? {
        BoundAddress::Fixed(length) => length,
        BoundAddress::Domain => {
            let [length] = read_array(stream).await?;
            usize::from(length).saturating_add(2)
        }
    };
    let mut bound = [0u8; 255 + 2];
    let bound = bound.get_mut(..remaining).ok_or(SocksError::Protocol)?;
    stream.read_exact(bound).await.map_err(SocksError::Io)?;
    Ok(())
}

async fn read_array<S: AsyncRead + Unpin, const N: usize>(
    stream: &mut S,
) -> Result<[u8; N], SocksError> {
    let mut buffer = [0u8; N];
    stream
        .read_exact(&mut buffer)
        .await
        .map_err(SocksError::Io)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips_and_success_is_none() {
        assert_eq!(SocksReply::from_code(0), None);
        for code in 1..=u8::MAX {
            assert_eq!(SocksReply::from_code(code).unwrap().code(), code);
        }
    }

    #[test]
    fn tor_replies_are_grouped_as_the_gui_shows_them() {
        let class = |code| SocksReply::from_code(code).unwrap().class();
        for code in [0xF0, 0xF2, 0xF7, 0x04, 0x05] {
            assert_eq!(class(code), SendFailure::Unreachable, "{code:#x}");
        }
        assert_eq!(class(0xF6), SendFailure::InvalidAddress);
        assert_eq!(class(0xF4), SendFailure::ClientAuth);
        assert_eq!(class(0xF5), SendFailure::ClientAuth);
        for code in [0x01, 0x06, 0xF1, 0xF3, 0x99] {
            assert_eq!(class(code), SendFailure::Broken, "{code:#x}");
        }
    }

    #[test]
    fn encodes_the_requests() {
        assert_eq!(encode_greeting(), [5, 1, 2]);
        let credentials = SocksCredentials {
            username: "ab".into(),
            password: "c".into(),
        };
        assert_eq!(
            encode_auth(&credentials).unwrap(),
            [1, 2, b'a', b'b', 1, b'c']
        );
        assert_eq!(
            encode_connect("x.onion", 80).unwrap(),
            [
                5, 1, 0, 3, 7, b'x', b'.', b'o', b'n', b'i', b'o', b'n', 0, 80
            ]
        );
        assert!(matches!(
            encode_connect(&"a".repeat(256), 80),
            Err(SocksError::HostTooLong)
        ));
        assert!(matches!(
            encode_connect("", 80),
            Err(SocksError::HostTooLong)
        ));
    }

    #[test]
    fn reads_the_replies() {
        assert!(parse_method_reply([5, 2]).is_ok());
        assert!(matches!(
            parse_method_reply([5, 0xFF]),
            Err(SocksError::AuthRefused)
        ));
        assert!(matches!(
            parse_method_reply([4, 2]),
            Err(SocksError::Protocol)
        ));
        assert!(parse_auth_reply([1, 0]).is_ok());
        assert!(matches!(
            parse_auth_reply([1, 1]),
            Err(SocksError::AuthRefused)
        ));
        assert!(matches!(
            parse_auth_reply([5, 0]),
            Err(SocksError::Protocol)
        ));
        assert_eq!(
            parse_connect_head([5, 0, 0, 1]).unwrap(),
            BoundAddress::Fixed(6)
        );
        assert_eq!(
            parse_connect_head([5, 0, 0, 4]).unwrap(),
            BoundAddress::Fixed(18)
        );
        assert_eq!(
            parse_connect_head([5, 0, 0, 3]).unwrap(),
            BoundAddress::Domain
        );
        assert!(matches!(
            parse_connect_head([5, 0xF6, 0, 1]),
            Err(SocksError::Refused(SocksReply::OnionAddressInvalid))
        ));
        assert!(matches!(
            parse_connect_head([5, 0, 0, 9]),
            Err(SocksError::Protocol)
        ));
        assert!(matches!(
            parse_connect_head([4, 0, 0, 1]),
            Err(SocksError::Protocol)
        ));
    }

    #[test]
    fn random_credentials_differ_and_stay_redacted() {
        let a = SocksCredentials::random().unwrap();
        let b = SocksCredentials::random().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.username.len(), 2 * CREDENTIAL_BYTES);
        assert_eq!(format!("{a:?}"), "SocksCredentials([redacted])");
    }
}
