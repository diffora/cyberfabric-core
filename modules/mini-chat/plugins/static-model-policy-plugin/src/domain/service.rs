use mini_chat_sdk::{KillSwitches, ModelCatalogEntry, TierLimits};
use modkit_macros::domain_model;

/// Service holding the model catalog loaded from configuration.
#[domain_model]
pub struct Service {
    pub catalog: Vec<ModelCatalogEntry>,
    pub kill_switches: KillSwitches,
    pub default_standard_limits: TierLimits,
    pub default_premium_limits: TierLimits,
}

impl Service {
    /// Create a service with the given configuration.
    #[must_use]
    pub fn new(
        catalog: Vec<ModelCatalogEntry>,
        kill_switches: KillSwitches,
        default_standard_limits: TierLimits,
        default_premium_limits: TierLimits,
    ) -> Self {
        Self {
            catalog,
            kill_switches,
            default_standard_limits,
            default_premium_limits,
        }
    }
}
