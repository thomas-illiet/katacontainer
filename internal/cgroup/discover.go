package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Discover(root, procCgroup, podUID string) (string, error) {
	if podUID == "" {
		return "", fmt.Errorf("pod UID is required")
	}
	f, err := os.Open(procCgroup)
	if err != nil {
		return "", fmt.Errorf("open cgroup membership: %w", err)
	}
	defer f.Close()
	var relative string
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			relative = parts[2]
			break
		}
	}
	if err := s.Err(); err != nil {
		return "", fmt.Errorf("scan cgroup membership: %w", err)
	}
	if relative == "" {
		return "", fmt.Errorf("cgroup v2 unified membership not found")
	}
	needle := strings.ReplaceAll(strings.ToLower(podUID), "-", "")
	candidate := filepath.Clean(filepath.Join(root, relative))
	cleanRoot := filepath.Clean(root)
	for strings.HasPrefix(candidate, cleanRoot+string(os.PathSeparator)) {
		base := strings.ReplaceAll(strings.ToLower(filepath.Base(candidate)), "-", "")
		base = strings.ReplaceAll(base, "_", "")
		if strings.Contains(base, needle) {
			if _, err := os.Stat(filepath.Join(candidate, "cgroup.procs")); err != nil {
				return "", fmt.Errorf("validate pod cgroup %q: %w", candidate, err)
			}
			return candidate, nil
		}
		candidate = filepath.Dir(candidate)
	}
	return "", fmt.Errorf("no cgroup ancestor matched pod UID %q", podUID)
}
