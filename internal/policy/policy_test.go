package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "policy.json")
	data := []byte(`{"egress":[{"cidrs":["10.0.0.0/8"],"protocol":"UDP","ports":[53]}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Protocol != ProtocolUDP {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("expected a read error")
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("expected a decode error")
		}
	})
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	entries, err := Normalize(Document{Egress: []Rule{
		{CIDRs: []string{"10.20.1.7/16", "2001:db8::/32"}, Protocol: "tcp", Ports: []uint16{443}},
		{CIDRs: []string{"10.20.0.0/16"}, Protocol: "TCP", Ports: []uint16{443}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(entries), 2; got != want {
		t.Fatalf("got %d entries, want %d", got, want)
	}
	if got := entries[0].Prefix.String(); got != "10.20.0.0/16" {
		t.Fatalf("prefix was not masked: %s", got)
	}
}

func TestNormalizeRejectsInvalidPolicies(t *testing.T) {
	t.Parallel()
	tests := []Document{
		{},
		{Egress: []Rule{{Protocol: "TCP", Ports: []uint16{443}}}},
		{Egress: []Rule{{CIDRs: []string{"bad"}, Protocol: "TCP", Ports: []uint16{443}}}},
		{Egress: []Rule{{CIDRs: []string{"10.0.0.0/8"}, Protocol: "SCTP", Ports: []uint16{443}}}},
		{Egress: []Rule{{CIDRs: []string{"10.0.0.0/8"}, Protocol: "TCP", Ports: []uint16{0}}}},
	}
	for i, doc := range tests {
		if _, err := Normalize(doc); err == nil {
			t.Errorf("case %d unexpectedly succeeded", i)
		}
	}
}

func TestNormalizeSortsProtocolsAndPorts(t *testing.T) {
	t.Parallel()
	entries, err := Normalize(Document{Egress: []Rule{
		{CIDRs: []string{"10.0.0.0/8"}, Protocol: "UDP", Ports: []uint16{53}},
		{CIDRs: []string{"10.0.0.0/8"}, Protocol: "TCP", Ports: []uint16{443, 80}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Port != 80 || entries[1].Port != 443 || entries[2].Protocol != ProtocolUDP {
		t.Fatalf("unexpected order: %#v", entries)
	}
}
