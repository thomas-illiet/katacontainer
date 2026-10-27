package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthcheckCommand(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	cmd.SetArgs([]string{"healthcheck", "--ready-file", ready})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("healthcheck failed: %v", err)
	}
}

func TestHealthcheckCommandFailsWithoutSignal(t *testing.T) {
	t.Parallel()
	cmd := newRootCommand()
	cmd.SetArgs([]string{"healthcheck", "--ready-file", filepath.Join(t.TempDir(), "missing")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("healthcheck unexpectedly succeeded")
	}
}

func TestHelpIsEnglish(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "Enforce an immutable cgroup eBPF egress allowlist") {
		t.Fatalf("unexpected help output: %s", got)
	}
}

func TestConfigureLoggerRejectsUnknownLevel(t *testing.T) {
	t.Parallel()
	if err := configureLogger("verbose"); err == nil {
		t.Fatal("unknown log level was accepted")
	}
}
