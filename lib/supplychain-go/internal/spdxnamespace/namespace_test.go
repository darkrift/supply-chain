package spdxnamespace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		wantErr   bool
	}{
		{
			name:      "absolute uri",
			namespace: "https://example.com/spdx/0f068793-f9b8-5cdd-9669-3ad9253ad3b7",
		},
		{
			name:      "empty",
			namespace: "",
			wantErr:   true,
		},
		{
			name:      "missing scheme",
			namespace: "example.com/spdx/name",
			wantErr:   true,
		},
		{
			name:      "fragment",
			namespace: "https://example.com/spdx/name#fragment",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q) error = %v, wantErr %v", tt.namespace, err, tt.wantErr)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "namespace.txt")
	if err := os.WriteFile(path, []byte("https://example.com/spdx/custom-namespace\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	want := "https://example.com/spdx/custom-namespace"
	if got != want {
		t.Errorf("ReadFile() = %q, want %q", got, want)
	}
}
