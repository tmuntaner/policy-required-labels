# Kubewarden policy Required Labels

## Description

This policy for [kubewarden](https://www.kubewarden.io) is a proof-of-concept to require certain labels with explicit values.

## Settings

This policy accepts the following configuration:

```yaml
# The labels you require
required_labels:
  - name: owner       # The name of the label
    allowed_values:   # The values you allow for the label
      - razor-crest
  - name: cost-center
    allowed_values:
      - cc-42
```

## Example KubeWarden ClusterAdmissionPolicy

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: required-labels
spec:
  module: registry://ghcr.io/tmuntaner/policies/required-labels:latest
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  mutating: false
  settings:
    required_labels:
      - name: owner
        allowed_values:
          - razor-crest
      - name: cost-center
        allowed_values:
          - cc-42
```
