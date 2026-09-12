# Cloud audit correlation and draft policies

The cloud audit package normalizes metadata-only events from AWS, GCP, and Azure into a common event shape. It accepts provider-exported JSON and extracts timestamp, principal, action, resource, environment, agent identity, and success state. It does not resolve credentials, call cloud APIs, read payloads, or retrieve secret values.

The policy package creates a `policy-draft.v1` object from runtime usage and normalized cloud resources. Drafts contain observed targets and operations, cloud resources correlated by stable agent ID, and an explicit `review_required: true` marker. Draft generation never blocks traffic, changes IAM, writes cloud policies, or enables enforcement automatically.

A future orchestration layer may load cloud events from CloudTrail, GCP Audit Logs, or Azure Activity Logs. That layer must make credentials and retention explicit, keep raw event payloads out of findings, and pass only normalized events into correlation.
