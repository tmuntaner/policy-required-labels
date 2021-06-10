extern crate wapc_guest as guest;
use guest::prelude::*;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    let required_labels = [String::from("owner"), String::from("cost-center")];

    match serde_json::from_value::<apicore::Pod>(validation_request.request.object) {
        Ok(pod) => {
            let mut missing_labels = Vec::new();

            match pod.metadata.labels {
                None => {
                    missing_labels = required_labels.to_vec();
                }
                Some(pod_labels) => {
                    for required_label in &required_labels {
                        if pod_labels.get(required_label) == None {
                            missing_labels.push(required_label.clone());
                        }
                    }
                }
            }

            if !missing_labels.is_empty() {
                let label = if missing_labels.len() == 1 {
                    format!("pod label {:?} is required", missing_labels)
                } else {
                    format!("pod labels {:?} are required", missing_labels)
                };

                return kubewarden::reject_request(Some(label), None);
            }

            kubewarden::accept_request()
        }
        Err(_) => kubewarden::accept_request(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn accept_pod_with_valid_name() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
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
            settings: Settings {},
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
    fn reject_pod_with_missing_label_cost_center() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_missing_label_cost_center.json";
        let tc = Testcase {
            name: String::from("missing label cost center"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
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
    fn reject_pod_with_missing_labels() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_missing_labels.json";
        let tc = Testcase {
            name: String::from("missing labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
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
    fn accept_request_with_non_pod_resource() -> Result<(), ()> {
        let request_file = "test_data/ingress_creation.json";
        let tc = Testcase {
            name: String::from("Ingress creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
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
