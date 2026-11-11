// SPDX-License-Identifier: Apache-2.0
//! The operations of the wallet API, one per `operationId` in `docs/api/openapi.json`. The router
//! names each request's operation, and serve answers it with the handler of that name.

macro_rules! ops {
    ($($op:ident = $id:literal,)*) => {
        /// One operation of the document.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) enum Op {
            $($op,)*
        }

        impl Op {
            /// Every operation, in the order the document lists them.
            pub(crate) const ALL: &[Self] = &[$(Self::$op,)*];

            /// The operation's `operationId`.
            pub(crate) const fn id(self) -> &'static str {
                match self {
                    $(Self::$op => $id,)*
                }
            }
        }
    };
}

ops! {
    GetStatus = "getStatus",
    GetOpenApi = "getOpenApi",
    GetWallet = "getWallet",
    UpdateWallet = "updateWallet",
    ChangeWalletPassword = "changeWalletPassword",
    ScanWallet = "scanWallet",
    SyncNow = "syncNow",
    ListAccounts = "listAccounts",
    CreateAccount = "createAccount",
    ListPayments = "listPayments",
    CreatePayment = "createPayment",
    EstimatePayment = "estimatePayment",
    GetPayment = "getPayment",
    UpdatePayment = "updatePayment",
    ApprovePayment = "approvePayment",
    DeclinePayment = "declinePayment",
    FinalizePayment = "finalizePayment",
    DeliverPayment = "deliverPayment",
    PostPayment = "postPayment",
    CancelPayment = "cancelPayment",
    GetPaymentHandoff = "getPaymentHandoff",
    Inspect = "inspect",
    Open = "open",
    ListOutputs = "listOutputs",
    ListAddresses = "listAddresses",
    CreateAddress = "createAddress",
    ListLinks = "listLinks",
    CreateLink = "createLink",
    RetireLink = "retireLink",
    ListContacts = "listContacts",
    CreateContact = "createContact",
    GetContact = "getContact",
    UpdateContact = "updateContact",
    DeleteContact = "deleteContact",
    VerifyContact = "verifyContact",
    CheckContact = "checkContact",
    ResolveContactKeys = "resolveContactKeys",
    MoveContact = "moveContact",
    SendPayload = "sendPayload",
    ExportContacts = "exportContacts",
    ImportContacts = "importContacts",
    ListPairRequests = "listPairRequests",
    AcceptPairRequest = "acceptPairRequest",
    DeletePairRequest = "deletePairRequest",
    ListPayloads = "listPayloads",
    DeletePayload = "deletePayload",
    ListQuarantine = "listQuarantine",
    RetryQuarantined = "retryQuarantined",
    DeleteQuarantined = "deleteQuarantined",
    GetRelay = "getRelay",
    MoveRelay = "moveRelay",
    GetNode = "getNode",
    ListPeers = "listPeers",
    DeletePeer = "deletePeer",
    GetProfile = "getProfile",
    UpdateProfile = "updateProfile",
    GetProfileDomainFile = "getProfileDomainFile",
    ListEvents = "listEvents",
}

impl Op {
    /// The operation with `operationId` `id`.
    pub(crate) fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|op| op.id() == id)
    }
}
