//! Commissioner public types.

use crate::meshcop::NetDiagData;

/// Commissioner state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionerState {
    /// Not connected.
    Disabled,
    /// UDP socket connected to a border agent; DTLS is not active.
    Connected,
    /// Petition request is in flight.
    Petitioning,
    /// Commissioner petition accepted.
    Active,
}

/// Events emitted by a commissioner session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommissionerEvent {
    /// Keepalive response status.
    KeepAliveResponse(ResultCode),
    /// Dataset changed notification.
    DatasetChanged,
    /// PAN ID conflict report.
    PanIdConflict {
        /// Reporting peer address.
        peer_addr: String,
        /// Channel mask used for the scan.
        channel_mask: u32,
        /// Conflicting PAN ID.
        pan_id: u16,
    },
    /// Energy scan report.
    EnergyReport {
        /// Reporting peer address.
        peer_addr: String,
        /// Channel mask used for the scan.
        channel_mask: u32,
        /// Energy list in dBm.
        energy_list: Vec<u8>,
    },
    /// Raw joiner proxy payload.
    JoinerMessage {
        /// Joiner ID.
        joiner_id: Vec<u8>,
        /// Joiner UDP port.
        port: u16,
        /// Payload bytes.
        payload: Vec<u8>,
    },
    /// DIAG_GET.ans network diagnostic answer.
    DiagnosticAnswer {
        /// Reporting peer address.
        peer_addr: String,
        /// Decoded network diagnostic TLVs.
        data: Box<NetDiagData>,
    },
    /// A joiner completed its DTLS handshake with the commissioner.
    JoinerConnected {
        /// Joiner ID.
        joiner_id: [u8; 8],
    },
    /// A joiner's JOIN_FIN.req was answered.
    JoinerFinalized {
        /// Joiner ID.
        joiner_id: [u8; 8],
        /// Whether the joiner was accepted.
        accepted: bool,
        /// Vendor information from the request.
        info: super::joiner::JoinerFinalizeInfo,
    },
}

/// MeshCoP result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    /// Accepted.
    Accept,
    /// Rejected.
    Reject,
    /// Pending.
    Pending,
}

/// Petition response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetitionResponse {
    /// Allocated commissioner session ID.
    pub session_id: u16,
    /// Existing commissioner ID when the petition is rejected by an active commissioner.
    pub existing_commissioner_id: Option<String>,
}

/// Active and pending operational dataset TLV flags used by MeshCoP get requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatasetFlags(u64);

impl DatasetFlags {
    /// Empty flag set.
    pub const EMPTY: Self = Self(0);
    /// All known flags set.
    pub const ALL: Self = Self(u64::MAX);
    /// Active dataset: Active Timestamp.
    pub const ACTIVE_TIMESTAMP: Self = Self(1 << 15);
    /// Active dataset: Channel.
    pub const CHANNEL: Self = Self(1 << 14);
    /// Active dataset: Channel Mask.
    pub const CHANNEL_MASK: Self = Self(1 << 13);
    /// Active dataset: Extended PAN ID.
    pub const EXTENDED_PAN_ID: Self = Self(1 << 12);
    /// Active dataset: Mesh-Local Prefix.
    pub const MESH_LOCAL_PREFIX: Self = Self(1 << 11);
    /// Active dataset: Network Key.
    pub const NETWORK_KEY: Self = Self(1 << 10);
    /// Active dataset: Network Name.
    pub const NETWORK_NAME: Self = Self(1 << 9);
    /// Active dataset: PAN ID.
    pub const PAN_ID: Self = Self(1 << 8);
    /// Active dataset: PSKc.
    pub const PSKC: Self = Self(1 << 7);
    /// Active dataset: Security Policy.
    pub const SECURITY_POLICY: Self = Self(1 << 6);
    /// Pending dataset: Delay Timer.
    pub const DELAY_TIMER: Self = Self(1 << 5);
    /// Pending dataset: Pending Timestamp.
    pub const PENDING_TIMESTAMP: Self = Self(1 << 4);
    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns whether every bit in `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for DatasetFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DatasetFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Commissioner dataset TLV flags used by MeshCoP commissioner and BBR get requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommissionerDatasetFlags(u64);

impl CommissionerDatasetFlags {
    /// Empty flag set.
    pub const EMPTY: Self = Self(0);
    /// All known flags set.
    pub const ALL: Self = Self(u64::MAX);
    /// Border Agent Locator.
    pub const BORDER_AGENT_LOCATOR: Self = Self(1 << 15);
    /// Commissioner Session ID.
    pub const COMMISSIONER_SESSION_ID: Self = Self(1 << 14);
    /// Steering Data.
    pub const STEERING_DATA: Self = Self(1 << 13);
    /// AE Steering Data.
    pub const AE_STEERING_DATA: Self = Self(1 << 12);
    /// NMKP Steering Data.
    pub const NMKP_STEERING_DATA: Self = Self(1 << 11);
    /// Joiner UDP Port.
    pub const JOINER_UDP_PORT: Self = Self(1 << 10);
    /// AE UDP Port.
    pub const AE_UDP_PORT: Self = Self(1 << 9);
    /// NMKP UDP Port.
    pub const NMKP_UDP_PORT: Self = Self(1 << 8);

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns whether every bit in `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for CommissionerDatasetFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for CommissionerDatasetFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
