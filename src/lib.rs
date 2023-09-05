use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, warn, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "sample-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");

    if validation_request.request.kind.kind != "Pod" {
        return kubewarden::accept_request();
    }

    // TODO: you can unmarshal any Kubernetes API type you are interested in
    match serde_json::from_value::<apicore::Pod>(validation_request.request.object) {
        Ok(pod) => {
            let mut missing_labels: Vec<String> = Vec::new();

            let required_labels = validation_request
                .settings
                .required_labels
                .unwrap_or_default();

            match pod.metadata.labels {
                None => {
                    for required_label in &required_labels {
                        let label = required_label.name.as_ref().unwrap().to_string();
                        missing_labels.push(label);
                    }
                }
                Some(pod_labels) => {
                    for required_label in &required_labels {
                        let label_name = required_label.name.as_ref().unwrap().to_string();

                        match pod_labels.get(label_name.as_str()) {
                            Some(value) => {
                                let allowed_values =
                                    required_label.allowed_values.as_ref().unwrap();

                                if !allowed_values.contains(&value.to_string()) {
                                    let message = format!(
                                        "invalid value for label '{}: {}'",
                                        label_name, value
                                    );

                                    return kubewarden::reject_request(
                                        Some(message),
                                        None,
                                        None,
                                        None,
                                    );
                                }
                            }
                            None => {
                                missing_labels.push(label_name);
                            }
                        }
                    }
                }
            }

            if !missing_labels.is_empty() {
                let message = if missing_labels.len() == 1 {
                    format!("pod label '{}' is required", missing_labels.join(", "))
                } else {
                    format!("pod labels '{}' are required", missing_labels.join(", "))
                };

                return kubewarden::reject_request(Some(message), None, None, None);
            }

            info!(LOG_DRAIN, "accepting resource");
            return kubewarden::accept_request();
        }
        Err(_) => {
            // TODO: handle as you wish
            // We were forwarded a request we cannot unmarshal or
            // understand, just accept it
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::settings::RequiredLabel;
    use kubewarden_policy_sdk::test::Testcase;

    fn generate_settings() -> Settings {
        let mut labels: Vec<RequiredLabel> = Vec::new();
        labels.push(RequiredLabel {
            name: Some("owner".to_string()),
            allowed_values: Some(["razor-crest".to_string()].to_vec()),
        });

        labels.push(RequiredLabel {
            name: Some("cost-center".to_string()),
            allowed_values: Some(["cc-42".to_string()].to_vec()),
        });

        Settings {
            required_labels: Some(labels),
        }
    }

    #[test]
    fn accept_pod_with_valid_name() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_with_missing_label_owner() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_missing_label_owner.json";
        let tc = Testcase {
            name: String::from("missing label owner"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        assert_eq!(
            res.message.unwrap(),
            String::from("pod label 'owner' is required")
        );

        Ok(())
    }

    #[test]
    fn reject_pod_with_missing_label_cost_center() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_missing_label_cost_center.json";
        let tc = Testcase {
            name: String::from("missing label cost center"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        assert_eq!(
            res.message.unwrap(),
            String::from("pod label 'cost-center' is required")
        );

        Ok(())
    }

    #[test]
    fn reject_pod_with_missing_labels() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_missing_labels.json";
        let tc = Testcase {
            name: String::from("missing labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        assert_eq!(
            res.message.unwrap(),
            String::from("pod labels 'owner, cost-center' are required")
        );

        Ok(())
    }

    #[test]
    fn reject_pod_with_invalid_label_owner() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_label_owner.json";
        let tc = Testcase {
            name: String::from("invalid label owner"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        assert_eq!(
            res.message.unwrap(),
            String::from("invalid value for label 'owner: foobar'")
        );

        Ok(())
    }

    #[test]
    fn accept_request_with_non_pod_resource() -> Result<(), ()> {
        let request_file = "test_data/ingress_creation.json";
        let tc = Testcase {
            name: String::from("Ingress creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: generate_settings(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
