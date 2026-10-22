/// Dart bindings for the LEPIC wallet engine.
///
/// Call `RustLib.init()` once, create one [LepicRuntime], and give every wallet an
/// [AppSecretStore] built by [lepicSecretStore] over the app's secure storage.
library;

import 'src/rust/api/secret_store.dart';

export 'src/rust/api/diagnostics.dart';
export 'src/rust/api/error.dart';
export 'src/rust/api/http.dart';
export 'src/rust/api/runtime.dart';
export 'src/rust/api/secret_store.dart';
export 'src/rust/api/testing.dart';
export 'src/rust/api/tor.dart';
export 'src/rust/api/types.dart';
export 'src/rust/api/wallet.dart';
export 'src/rust/frb_generated.dart' show RustLib;

/// The key-value storage LEPIC keeps a wallet's encrypted vault, PIN key and PIN failure count
/// in, such as `flutter_secure_storage`. One store per wallet: the keys have fixed names.
abstract interface class SecretStore {
  Future<String?> read(String key);

  Future<void> write(String key, String value);

  Future<void> delete(String key);
}

/// Wraps [store] for LEPIC. An exception thrown by [store] fails the LEPIC call with
/// `WalletErrorKind.secretStore` instead of leaving it unanswered.
AppSecretStore lepicSecretStore(SecretStore store) => AppSecretStore(
  read: (key) => _reply(() async => store.read(key)),
  write: (key, value) => _reply(() async {
    await store.write(key, value);
    return null;
  }),
  delete: (key) => _reply(() async {
    await store.delete(key);
    return null;
  }),
);

Future<SecretReply> _reply(Future<String?> Function() call) async {
  try {
    return SecretReply(ok: true, value: await call());
  } on Object {
    return const SecretReply(ok: false);
  }
}
