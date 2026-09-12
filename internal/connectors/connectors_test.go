package connectors

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryNormalizesMetadataOnly(t *testing.T) {
	tests := []struct {
		kind    Kind
		payload string
		want    string
	}{
		{GitHub, `{"full_name":"HlinorAI/agent-control-plane","html_url":"https://github.com/HlinorAI/agent-control-plane","default_branch":"main","topics":["agents"]}`, "HlinorAI/agent-control-plane"},
		{GitLab, `{"path_with_namespace":"group/project","web_url":"https://gitlab.example/group/project","default_branch":"main"}`, "group/project"},
		{Docker, `{"RepoTags":["registry.example/agent:1.2.3"],"Config":{"Labels":{"owner":"security","secret":"must-not-be-read"}}}`, "registry.example/agent:1.2.3"},
		{Kubernetes, `{"kind":"Deployment","metadata":{"name":"support-agent","namespace":"production","labels":{"app":"support"},"annotations":{"owner":"security"}},"spec":{"env":[{"name":"TOKEN","value":"must-not-be-read"}]}}`, "production/support-agent"},
	}
	registry := NewRegistry()
	for _, test := range tests {
		metadata, err := registry.Normalize(test.kind, []byte(test.payload))
		if err != nil {
			t.Fatalf("Normalize(%s) error = %v", test.kind, err)
		}
		if metadata.Source.Locator != test.want && metadata.Repository != test.want && metadata.Project != test.want && metadata.Image != test.want {
			t.Fatalf("Normalize(%s) locator mismatch: %+v", test.kind, metadata)
		}
		if strings.Contains(string(mustJSON(metadata)), "must-not-be-read") {
			t.Fatalf("Normalize(%s) retained secret-like payload", test.kind)
		}
	}
}

func TestRegistryRejectsUnsupportedAndMalformedInput(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.Normalize("aws", []byte(`{}`)); err == nil {
		t.Fatal("unsupported connector accepted")
	}
	if _, err := registry.Normalize(GitHub, []byte(`[]`)); err == nil {
		t.Fatal("array payload accepted")
	}
}

func mustJSON(value Metadata) []byte { payload, _ := json.Marshal(value); return payload }
