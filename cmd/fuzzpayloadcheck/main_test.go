package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePayloadAcceptsSyntheticMCPMetadata(t *testing.T) {
	payload := []byte(`{"mcpServers":{"synthetic":{"type":"http","url":"https://example.invalid/mcp"}}}`)
	violations := validatePayload("/repo/testdata/fuzz/mcp_metadata/safe.json", payload, defaultMaxBytes)
	if len(violations) != 0 {
		t.Fatalf("safe payload rejected: %+v", violations)
	}
}

func TestValidatePayloadRejectsDangerousMCPCommand(t *testing.T) {
	payload := []byte(`{"packages":[{"transport":{"type":"stdio","command":"sh -c 'touch SHOULD_NOT_EXIST'"}}]}`)
	violations := validatePayload("/repo/testdata/fuzz/mcp_metadata/command.json", payload, defaultMaxBytes)
	assertViolationCode(t, violations, "dangerous_command")
}

func TestValidatePayloadRejectsUnsafeURL(t *testing.T) {
	payload := []byte(`{"server":{"url":"http://127.0.0.1:9/"}}`)
	violations := validatePayload("/repo/testdata/fuzz/mcp_metadata/loopback.json", payload, defaultMaxBytes)
	assertViolationCode(t, violations, "unsafe_url")
}

func TestValidatePayloadRejectsRealCredentialLikeValue(t *testing.T) {
	payload := []byte(`{"authorization":"Bearer abcdefghijklmnop1234"}`)
	violations := validatePayload("/repo/testdata/fuzz/tool_calls/credential.json", payload, defaultMaxBytes)
	assertViolationCode(t, violations, "secret_like_value")
}

func TestValidatePayloadAllowsSyntheticCredentialMarker(t *testing.T) {
	payload := []byte(`{"authorization":"Bearer SYNTHETIC-NOT-A-CREDENTIAL"}`)
	violations := validatePayload("/repo/testdata/fuzz/tool_calls/synthetic-credential.json", payload, defaultMaxBytes)
	if len(violations) != 0 {
		t.Fatalf("synthetic credential marker rejected: %+v", violations)
	}
}

func TestValidatePayloadRejectsDuplicateKeys(t *testing.T) {
	payload := []byte(`{"tool":"search","arguments":{"q":"one","q":"two"}}`)
	violations := validatePayload("/repo/testdata/fuzz/tool_calls/duplicate.json", payload, defaultMaxBytes)
	assertViolationCode(t, violations, "duplicate_key")
}

func TestValidatePayloadRejectsOversizedPayload(t *testing.T) {
	payload := []byte(`{"query":"synthetic"}`)
	violations := validatePayload("/repo/testdata/fuzz/tool_calls/oversized.json", payload, int64(len(payload)-1))
	assertViolationCode(t, violations, "size_limit")
}

func TestValidateRootAllowsExpectedAdversarialViolations(t *testing.T) {
	root := t.TempDir()
	payload := []byte(`{"server":{"url":"http://127.0.0.1:9/"}}`)
	if err := writeJSON(filepath.Join(root, "testdata", "fuzz", "mcp_metadata", "loopback.json"), payload); err != nil {
		t.Fatal(err)
	}
	strict, err := validateRoot(root, defaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if strict.BlockingViolations == 0 {
		t.Fatal("strict validation accepted an unsafe URL")
	}
	allowed, err := validateRootWithOptions(root, defaultMaxBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	if allowed.BlockingViolations != 0 {
		t.Fatalf("expected only allowed adversarial violations, got %+v", allowed)
	}
}

func TestValidateRootKeepsCredentialViolationsBlocking(t *testing.T) {
	root := t.TempDir()
	payload := []byte(`{"authorization":"Bearer abcdefghijklmnop1234"}`)
	if err := writeJSON(filepath.Join(root, "testdata", "fuzz", "tool_calls", "credential.json"), payload); err != nil {
		t.Fatal(err)
	}
	result, err := validateRootWithOptions(root, defaultMaxBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.BlockingViolations == 0 {
		t.Fatal("adversarial mode allowed a credential-like value")
	}
}

func TestIsSyntheticPathRequiresApprovedPathSegments(t *testing.T) {
	if !isSyntheticPath("/repo/testdata/fuzz/tool_calls/safe.json") {
		t.Fatal("approved fuzz path was rejected")
	}
	if isSyntheticPath("/repo/not-testdata/fuzz/tool_calls/safe.json") {
		t.Fatal("substring lookalike path was accepted")
	}
}

func writeJSON(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func assertViolationCode(t *testing.T, violations []violation, expected string) {
	t.Helper()
	for _, item := range violations {
		if item.Code == expected {
			return
		}
	}
	t.Fatalf("expected violation %q, got %+v", expected, violations)
}
