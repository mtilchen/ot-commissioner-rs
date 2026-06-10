//! Thread network diagnostic (TMF) data model and decoders.
//!
//! Mirrors the `NetDiagData` surface of the C++ `ot-commissioner` reference
//! (`include/commissioner/network_diag_data.hpp`) so DIAG_GET.ans payloads can
//! be decoded into typed values. The typed data model lives in [`model`], the
//! wire decoders in [`decode`], and the request flag bits in [`diag_flags`].

mod decode;
pub mod diag_flags;
mod model;

pub use model::{
    BorderRouterEntry, ChildIpv6AddrInfo, ChildTableEntry, Connectivity, HasRouteEntry, LeaderData,
    MacCounters, ModeData, NetDiagData, NetworkData, PrefixEntry, Route64, RouteDataEntry,
    SixLowPanContext,
};
