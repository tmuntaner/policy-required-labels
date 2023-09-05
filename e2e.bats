#!/usr/bin/env bats

@test "Accept a valid name" {
	run kwctl run  --request-path test_data/pod_creation.json --settings-path test_data/settings.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Reject invalid owner tag" {
	run kwctl run  --request-path test_data/pod_creation_invalid_label_owner.json --settings-path test_data/settings.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 }
