//! Commissioner configuration.

use std::time::Duration;

use zeroize::Zeroize;

use crate::{
    Result,
    crypto::{RecordProtectionKey, pskc_from_active_dataset},
    dataset::Dataset,
};

/// Commissioner configuration.
#[derive(Clone)]
pub struct CommissionerConfig {
    /// Human-readable commissioner ID.
    pub commissioner_id: String,
    /// PSKc for non-CCM commissioner authentication.
    pub pskc: RecordProtectionKey,
    /// Keepalive interval.
    pub keepalive_interval: Duration,
    /// Domain name reserved for future CCM flows.
    pub domain_name: String,
    /// CCM enable flag reserved for future token/certificate flows.
    pub enable_ccm: bool,
}

impl core::fmt::Debug for CommissionerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommissionerConfig")
            .field("commissioner_id", &self.commissioner_id)
            .field("pskc", &"<redacted>")
            .field("keepalive_interval", &self.keepalive_interval)
            .field("domain_name", &self.domain_name)
            .field("enable_ccm", &self.enable_ccm)
            .finish()
    }
}

impl CommissionerConfig {
    /// Creates a PSKc-based commissioner config.
    pub fn pskc(commissioner_id: impl Into<String>, pskc: [u8; 16]) -> Self {
        Self {
            commissioner_id: commissioner_id.into(),
            pskc: RecordProtectionKey::new(pskc),
            keepalive_interval: Duration::from_secs(40),
            domain_name: "Thread".to_string(),
            enable_ccm: false,
        }
    }

    /// Creates a config by extracting PSKc from a dataset.
    pub fn from_dataset(commissioner_id: impl Into<String>, dataset: &Dataset) -> Result<Self> {
        Ok(Self::pskc(
            commissioner_id,
            pskc_from_active_dataset(dataset)?,
        ))
    }
}
impl Drop for CommissionerConfig {
    fn drop(&mut self) {
        self.commissioner_id.zeroize();
        self.domain_name.zeroize();
    }
}
