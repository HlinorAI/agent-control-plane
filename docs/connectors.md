# Read-only connector metadata

The connector package defines a small normalization boundary for external discovery systems. It accepts already-fetched JSON metadata and returns a bounded `Metadata` object for inventory enrichment.

Supported kinds are GitHub repositories, GitLab projects, Docker image inspect metadata, and Kubernetes workload metadata. The package deliberately does not create network clients, resolve credentials, execute provider CLIs, or read Kubernetes Secret values. Those responsibilities belong to an explicit orchestration layer that can enforce user-selected credentials and audit access.

The normalized object contains only source locator, repository/project/image/workload identity, revision, namespace, labels, and annotations. Label and annotation keys or values containing secret, token, password, API key, authorization, or credential markers are discarded. Values are length-bounded and unsupported or malformed JSON is rejected.

A future connector implementation should satisfy:

```go
type Connector interface {
    Kind() Kind
    Normalize(payload []byte) (Metadata, error)
}
```

The local scan path remains deterministic and network-free. Connector discovery should be performed before scanning and passed into inventory as an explicit, reviewable input.
