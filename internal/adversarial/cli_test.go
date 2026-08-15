package adversarial

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCLIThresholdExitCodes(t *testing.T) {
	repositoryRoot := findRepositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "agentctl")
	build := exec.Command("go", "build", "-o", binary, "./cmd/agentctl")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agentctl: %v\n%s", err, output)
	}

	cases := []struct {
		name       string
		root       string
		threshold  string
		expectsErr bool
	}{
		{name: "demo-high", root: "testdata/demo", threshold: "high", expectsErr: true},
		{name: "demo-critical", root: "testdata/demo", threshold: "critical", expectsErr: true},
		{name: "regression-high", root: "testdata/regression", threshold: "high", expectsErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command(binary, "scan", tc.root, "--format", "json", "--fail-on", tc.threshold)
			command.Dir = repositoryRoot
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			gotError := errors.As(err, &exitError)
			if gotError != tc.expectsErr {
				t.Fatalf("expected command error=%t, got err=%v\n%s", tc.expectsErr, err, output)
			}
			if bytes.Contains(output, []byte("prod-api-token")) {
				t.Fatal("CLI output leaked a secret-like value")
			}
		})
	}
}
