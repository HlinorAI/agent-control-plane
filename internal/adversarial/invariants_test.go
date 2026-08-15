package adversarial

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HlinorAI/agent-control-plane/internal/scan"
)

func TestScanDoesNotContactMCPURLs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = connection.Close()
		}
	}()
	defer func() {
		_ = listener.Close()
		<-done
	}()

	root := t.TempDir()
	config := fmt.Sprintf(`{"mcpServers":{"synthetic":{"type":"http","url":"http://%s/mcp"}}}`, listener.Addr().String())
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Run(root, scan.Options{}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-accepted:
		t.Fatal("scanner contacted an MCP URL")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestScanMaintainsRootContainmentForSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "outside.py")
	content := []byte("name: outside-agent\nmodel: openai\n")
	if err := os.WriteFile(outsideFile, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.py")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	report, err := scan.Run(root, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Agents) != 0 {
		t.Fatalf("scanner read outside-root symlink: %+v", report.Agents)
	}
	for _, readFile := range report.ReadFiles {
		if filepath.Clean(readFile) == "linked.py" {
			t.Fatal("scanner included symlink target in read files")
		}
	}
}

func TestScanHandlesMalformedAndOversizedInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":`), 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, (1<<20)+1)
	copy(oversized, []byte("name: oversized-agent\nmodel: openai\n"))
	if err := os.WriteFile(filepath.Join(root, "oversized.py"), oversized, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := scan.Run(root, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesSkipped == 0 {
		t.Fatalf("expected malformed or oversized input to be skipped: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(string(encoded), '\x00') {
		t.Fatal("report contains unexpected control byte")
	}
}
