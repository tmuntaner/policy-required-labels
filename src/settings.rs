use crate::LOG_DRAIN;

use serde::{Deserialize, Serialize};
use slog::info;

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub required_labels: Option<Vec<RequiredLabel>>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub(crate) struct RequiredLabel {
    pub name: Option<String>,
    pub allowed_values: Option<Vec<String>>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() -> Result<(), ()> {
        let settings = Settings::default();

        assert!(settings.validate().is_ok());
        Ok(())
    }
}
