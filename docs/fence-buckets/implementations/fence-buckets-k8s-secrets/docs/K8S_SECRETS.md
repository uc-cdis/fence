# Kubernetes Secrets Integration

Two modes:

1. **Mount mode (default)** — `ref` is a file path to a JSON file mounted in the pod.
2. **API mode** — `ref` is `k8s://<namespace>/<secret-name>[:<key>]`.

Set env:
- `FENCE_K8S_SECRET_MODE=mount|api`
- `FENCE_K8S_NAMESPACE` (optional; defaults to pod namespace)

### Example Secret (API mode)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fence-minio-dev
  namespace: gen3
type: Opaque
stringData:
  credentials.json: |
    {"access_key_id":"EXAMPLEACCESS","secret_access_key":"EXAMPLESECRET"}
```

### RBAC (API mode)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fence-secret-reader
  namespace: gen3
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["fence-minio-dev"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fence-secret-reader-binding
  namespace: gen3
subjects:
  - kind: ServiceAccount
    name: fence
    namespace: gen3
roleRef:
  kind: Role
  name: fence-secret-reader
  apiGroup: rbac.authorization.k8s.io
```

### Helm snippet (mount mode)
```yaml
env:
  - name: FENCE_K8S_SECRET_MODE
    value: "mount"
volumeMounts:
  - name: fence-creds
    mountPath: /var/run/secrets/fence
volumes:
  - name: fence-creds
    secret:
      secretName: fence-minio-dev
```
