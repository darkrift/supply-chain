package main

import (
	"testing"
	"time"

	"github.com/bazel-contrib/supply-chain/lib/supplychain-go/internal/sbom"
)

func TestStampGraph(t *testing.T) {
	graph := []map[string]any{
		{"type": "CreationInfo", "created": "1970-01-01T00:00:00Z"},
		{"type": "SpdxDocument", "spdxId": "https://spdx.org/spdxdocs/x", "namespaceMap": []any{map[string]any{"prefix": "SPDXRef", "namespace": "https://spdx.org/spdxdocs/x#"}}},
		{"type": "software_Package", "spdxId": "SPDXRef:dep-0", "software_packageVersion": "1.0.0"},
		{"type": "software_Package", "spdxId": "SPDXRef:dep-1", "software_packageVersion": "2.0.0"},
	}
	status := sbom.BuildStatus{Created: time.Unix(1700000000, 0).UTC(), BuildVersion: "v1.2.3"}

	if err := stampGraph(graph, status, "https://example.com/spdx/acme"); err != nil {
		t.Fatal(err)
	}

	if got := graph[0]["created"]; got != "2023-11-14T22:13:20Z" {
		t.Errorf("created = %v", got)
	}
	if got := graph[1]["spdxId"]; got != "https://example.com/spdx/acme" {
		t.Errorf("document id = %v", got)
	}
	if got := graph[1]["namespaceMap"].([]any)[0].(map[string]any)["namespace"]; got != "https://example.com/spdx/acme#" {
		t.Errorf("namespace = %v", got)
	}
	if got := graph[2]["software_packageVersion"]; got != "v1.2.3" {
		t.Errorf("subject version = %v", got)
	}
	if got := graph[3]["software_packageVersion"]; got != "2.0.0" {
		t.Errorf("other version = %v", got)
	}
}

func TestStampGraphRejectsInvalidNamespace(t *testing.T) {
	graph := []map[string]any{{"type": "CreationInfo"}, {"type": "SpdxDocument"}}
	if err := stampGraph(graph, sbom.BuildStatus{}, "https://example.com/a#b"); err == nil {
		t.Fatal("want an error")
	}
}
