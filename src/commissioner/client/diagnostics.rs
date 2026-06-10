//! Network-diagnostic (TMF) queries and resets.

use std::net::Ipv6Addr;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CommissionerOperation, diag::NetDiagData},
};

use super::{Commissioner, check_state_response, commissioner_trace};

impl Commissioner {
    /// Queries diagnostic TLVs from `destination`, or the leader when `None`.
    ///
    /// This uses the DIAG_GET.qry resource, whose answers arrive asynchronously
    /// as [`CommissionerEvent::DiagnosticAnswer`](super::super::CommissionerEvent::DiagnosticAnswer).
    /// For a single node, prefer [`Commissioner::get_diagnostics`].
    pub async fn diagnostic_get(
        &mut self,
        destination: Option<Ipv6Addr>,
        flags: u64,
    ) -> Result<()> {
        self.session_id_required()?;
        let destination = match destination {
            Some(destination) => destination,
            None => self.leader_aloc().await?,
        };
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::diagnostic_request(
            CommissionerOperation::DiagnosticGet,
            message_id,
            token,
            flags,
            true,
        )?;
        let response = self
            .execute_proxied(CommissionerOperation::DiagnosticGet, request, destination)
            .await?;
        check_state_response(&response, false)
    }

    /// Fetches network-diagnostic TLVs from a single `destination` over the
    /// unicast DIAG_GET.req (`/d/dg`) resource, returning the decoded answer.
    ///
    /// Unlike [`Commissioner::diagnostic_get`] (which uses the DIAG_GET.qry
    /// resource whose answers arrive asynchronously as
    /// [`CommissionerEvent::DiagnosticAnswer`](super::super::CommissionerEvent::DiagnosticAnswer)),
    /// the unicast request carries the requested TLVs piggybacked in its
    /// response, so the answer is returned directly. This is the resource to use
    /// when walking a mesh node by node.
    ///
    /// Requires an active commissioner session. `destination` must be a unicast
    /// mesh address; the DIAG_GET.req resource is unicast-only (use
    /// [`Commissioner::diagnostic_get`] for a multicast query).
    pub async fn get_diagnostics(
        &mut self,
        destination: Ipv6Addr,
        flags: u64,
    ) -> Result<NetDiagData> {
        self.session_id_required()?;
        if destination.is_multicast() {
            return Err(Error::InvalidState(
                "get_diagnostics requires a unicast destination; use diagnostic_get for a query",
            ));
        }
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::diagnostic_request(
            CommissionerOperation::DiagnosticGetUnicast,
            message_id,
            token,
            flags,
            true,
        )?;
        let response = self
            .execute_proxied(
                CommissionerOperation::DiagnosticGetUnicast,
                request,
                destination,
            )
            .await?;
        // Reject only genuine CoAP error responses (class 4 client-error or 5
        // server-error) so a node's failure is surfaced instead of being
        // silently decoded as an empty answer. Any 2.xx success response is
        // handed to the tolerant decoder, which copes with the per-vendor code
        // variations seen in the field.
        let class = response.code.0 >> 5;
        if class == 4 || class == 5 {
            commissioner_trace(format_args!(
                "DIAG_GET.req returned CoAP error code 0x{:02x}",
                response.code.0
            ));
            return Err(Error::InvalidState(
                "DIAG_GET.req returned a CoAP error response",
            ));
        }
        NetDiagData::decode(&response.payload)
    }

    /// Resets diagnostic TLVs on `destination`, or the leader when `None`.
    pub async fn diagnostic_reset(
        &mut self,
        destination: Option<Ipv6Addr>,
        flags: u64,
    ) -> Result<()> {
        self.session_id_required()?;
        let destination = match destination {
            Some(destination) => destination,
            None => self.leader_aloc().await?,
        };
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::diagnostic_request(
            CommissionerOperation::DiagnosticReset,
            message_id,
            token,
            flags,
            true,
        )?;
        let response = self
            .execute_proxied(CommissionerOperation::DiagnosticReset, request, destination)
            .await?;
        check_state_response(&response, false)
    }
}
