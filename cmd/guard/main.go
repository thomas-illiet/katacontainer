package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/example/kata-egress-guard/internal/cgroup"
	"github.com/example/kata-egress-guard/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

const metricCount = 6

type config struct {
	policyPath string
	cgroupRoot string
	procCgroup string
	podUID     string
	readyFile  string
	pinPath    string
	listen     string
	runUID     int
	runGID     int
}

type ipv4Key struct {
	PrefixLen uint32
	Protocol  uint8
	Pad       uint8
	Port      [2]byte
	Address   [4]byte
}

type ipv6Key struct {
	PrefixLen uint32
	Protocol  uint8
	Pad       uint8
	Port      [2]byte
	Address   [16]byte
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := newRootCommand().Execute(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	if runtime.GOOS != "linux" {
		return errors.New("kata-egress-guard requires Linux")
	}
	if !strings.HasPrefix(filepath.Clean(cfg.pinPath), "/sys/fs/bpf/") {
		return errors.New("pin path must be below /sys/fs/bpf")
	}
	entries, err := policy.Load(cfg.policyPath)
	if err != nil {
		return err
	}
	podCgroup, err := cgroup.Discover(cfg.cgroupRoot, cfg.procCgroup, cfg.podUID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.pinPath); err == nil {
		return fmt.Errorf("pin directory %q already exists; refusing to detach or replace an active policy", cfg.pinPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pin directory: %w", err)
	}
	if err := os.MkdirAll(cfg.pinPath, 0o700); err != nil {
		return fmt.Errorf("create pin directory: %w", err)
	}

	var objs kataObjects
	if err := loadKataObjects(&objs, nil); err != nil {
		return fmt.Errorf("load and verify eBPF: %w", err)
	}
	defer objs.Close()
	if err := populatePolicy(&objs, entries); err != nil {
		return err
	}
	if err := objs.AllowedIpv4.Freeze(); err != nil {
		return fmt.Errorf("freeze IPv4 policy: %w", err)
	}
	if err := objs.AllowedIpv6.Freeze(); err != nil {
		return fmt.Errorf("freeze IPv6 policy: %w", err)
	}

	attachments := []struct {
		name   string
		prog   *ebpf.Program
		typeID ebpf.AttachType
	}{
		{"connect4", objs.GuardConnect4, ebpf.AttachCGroupInet4Connect},
		{"connect6", objs.GuardConnect6, ebpf.AttachCGroupInet6Connect},
		{"sendmsg4", objs.GuardSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{"sendmsg6", objs.GuardSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
		{"sock-create", objs.GuardSockCreate, ebpf.AttachCGroupInetSockCreate},
	}
	links := make([]link.Link, 0, len(attachments))
	defer func() {
		for _, item := range links {
			item.Close()
		}
	}()
	for _, attachment := range attachments {
		item, err := link.AttachCgroup(link.CgroupOptions{Path: podCgroup, Attach: attachment.typeID, Program: attachment.prog})
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", attachment.name, podCgroup, err)
		}
		if err := item.Pin(filepath.Join(cfg.pinPath, attachment.name)); err != nil {
			item.Close()
			return fmt.Errorf("pin %s link: %w", attachment.name, err)
		}
		links = append(links, item)
	}

	collector := newCounterCollector(objs.Counters)
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	if err := signalReady(cfg.readyFile); err != nil {
		return err
	}
	if err := dropPrivileges(cfg.runUID, cfg.runGID); err != nil {
		return err
	}
	slog.Info("egress guard active", "cgroup", podCgroup, "rules", len(entries))
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}

func populatePolicy(objs *kataObjects, entries []policy.Entry) error {
	one := uint8(1)
	for _, entry := range entries {
		port := [2]byte{}
		binary.BigEndian.PutUint16(port[:], entry.Port)
		address := entry.Prefix.Addr()
		if address.Is4() {
			key := ipv4Key{PrefixLen: uint32(32 + entry.Prefix.Bits()), Protocol: entry.Protocol, Port: port, Address: address.As4()}
			if err := objs.AllowedIpv4.Put(key, one); err != nil {
				return fmt.Errorf("insert IPv4 rule %s: %w", describe(entry), err)
			}
		} else {
			key := ipv6Key{PrefixLen: uint32(32 + entry.Prefix.Bits()), Protocol: entry.Protocol, Port: port, Address: address.As16()}
			if err := objs.AllowedIpv6.Put(key, one); err != nil {
				return fmt.Errorf("insert IPv6 rule %s: %w", describe(entry), err)
			}
		}
	}
	return nil
}

func describe(entry policy.Entry) string {
	return fmt.Sprintf("%s protocol=%d port=%d", entry.Prefix, entry.Protocol, entry.Port)
}

func signalReady(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create ready directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("ready\n"), 0o444); err != nil {
		return fmt.Errorf("write ready signal: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish ready signal: %w", err)
	}
	return nil
}

func dropPrivileges(uid, gid int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("drop supplementary groups: %w", err)
	}
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("drop GID: %w", err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("drop UID: %w", err)
	}
	return nil
}
