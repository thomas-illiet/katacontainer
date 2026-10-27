package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	pod := filepath.Join(root, "kubepods.slice", "pod1234abcd")
	container := filepath.Join(pod, "container.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	proc := filepath.Join(root, "proc-cgroup")
	rel, _ := filepath.Rel(root, container)
	if err := os.WriteFile(proc, []byte("0::/"+rel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Discover(root, proc, "1234-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got != pod {
		t.Fatalf("got %q, want %q", got, pod)
	}
}

func TestDiscoverFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	proc := filepath.Join(root, "proc-cgroup")
	if err := os.WriteFile(proc, []byte("0::/unrelated/container\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root, proc, "1234-abcd"); err == nil {
		t.Fatal("expected ambiguous cgroup discovery to fail")
	}
}

func TestDiscoverErrors(t *testing.T) {
	t.Parallel()
	t.Run("empty pod UID", func(t *testing.T) {
		if _, err := Discover(t.TempDir(), "unused", ""); err == nil {
			t.Fatal("expected an empty UID error")
		}
	})
	t.Run("missing membership", func(t *testing.T) {
		if _, err := Discover(t.TempDir(), filepath.Join(t.TempDir(), "missing"), "pod"); err == nil {
			t.Fatal("expected an open error")
		}
	})
	t.Run("membership read error", func(t *testing.T) {
		directory := t.TempDir()
		if _, err := Discover(t.TempDir(), directory, "pod"); err == nil {
			t.Fatal("expected a scan error")
		}
	})
	t.Run("not unified cgroup v2", func(t *testing.T) {
		root := t.TempDir()
		proc := filepath.Join(root, "proc-cgroup")
		if err := os.WriteFile(proc, []byte("2:cpu:/legacy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Discover(root, proc, "pod"); err == nil {
			t.Fatal("expected a cgroup v2 error")
		}
	})
	t.Run("matched cgroup missing control file", func(t *testing.T) {
		root := t.TempDir()
		pod := filepath.Join(root, "pod1234")
		container := filepath.Join(pod, "container")
		if err := os.MkdirAll(container, 0o755); err != nil {
			t.Fatal(err)
		}
		proc := filepath.Join(root, "proc-cgroup")
		if err := os.WriteFile(proc, []byte("0::/pod1234/container\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Discover(root, proc, "1234"); err == nil {
			t.Fatal("expected cgroup validation to fail")
		}
	})
}
