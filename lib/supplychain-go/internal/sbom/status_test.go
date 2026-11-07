package sbom_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func TestReadBuildStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(path, []byte("BUILD_TIMESTAMP 1700000000\nSTABLE_BUILD_VERSION 1.2.3\nSTABLE_GIT_COMMIT abc123\nSTABLE_VCS_REVISION https://example.com/repo/commit/abc123\nSTABLE_SBOM_SERIAL_NUMBER urn:uuid:11111111-2222-3333-4444-555555555555\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := sbom.ReadBuildStatus(path)
	if err != nil {
		t.Fatalf("ReadBuildStatus() error = %v", err)
	}
	if !got.Created.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Errorf("Created = %v, want timestamp from BUILD_TIMESTAMP", got.Created)
	}
	if got.Version() != "1.2.3" {
		t.Errorf("Version() = %q, want build version", got.Version())
	}
	if got.RevisionURL() != "https://example.com/repo/commit/abc123" {
		t.Errorf("RevisionURL() = %q, want VCS revision URL", got.RevisionURL())
	}
	if got.SerialNumber != "urn:uuid:11111111-2222-3333-4444-555555555555" {
		t.Errorf("SerialNumber = %q, want stamped serial number", got.SerialNumber)
	}
}

func TestReadBuildStatusDefaultsToEpoch(t *testing.T) {
	got, err := sbom.ReadBuildStatus("")
	if err != nil {
		t.Fatalf("ReadBuildStatus(\"\") error = %v", err)
	}
	if !got.Created.Equal(time.Unix(0, 0).UTC()) {
		t.Errorf("Created = %v, want Unix epoch", got.Created)
	}
}
