package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newRootCommand() *cobra.Command {
	v := viper.New()
	v.SetEnvPrefix("KATA_EGRESS_GUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	cmd := &cobra.Command{
		Use:           "kata-egress-guard",
		Short:         "Enforce an immutable cgroup eBPF egress allowlist in a Kata guest",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return configureLogger(v.GetString("log-level"))
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config{
				policyPath: v.GetString("policy"),
				cgroupRoot: v.GetString("cgroup-root"),
				procCgroup: v.GetString("proc-cgroup"),
				podUID:     v.GetString("pod-uid"),
				readyFile:  v.GetString("ready-file"),
				pinPath:    v.GetString("pin-path"),
				listen:     v.GetString("listen"),
				runUID:     v.GetInt("run-uid"),
				runGID:     v.GetInt("run-gid"),
			}
			return run(cfg)
		},
	}

	flags := cmd.Flags()
	flags.String("policy", "/etc/kata-egress-guard/policy.json", "Path to the JSON policy document")
	flags.String("cgroup-root", "/sys/fs/cgroup", "Path to the cgroup v2 mount")
	flags.String("proc-cgroup", "/proc/self/cgroup", "Path to the current process cgroup membership")
	flags.String("pod-uid", "", "Kubernetes Pod UID used to identify the parent cgroup")
	flags.String("ready-file", "/run/kata-egress-guard/ready", "Path to the readiness signal")
	flags.String("pin-path", "/sys/fs/bpf/kata-egress-guard", "bpffs directory used to pin links")
	flags.String("listen", "127.0.0.1:9090", "Metrics and health HTTP listen address")
	flags.Int("run-uid", 65532, "UID used after eBPF attachment")
	flags.Int("run-gid", 65532, "GID used after eBPF attachment")
	flags.String("log-level", "info", "Structured log level: debug, info, warn, or error")
	if err := v.BindPFlags(flags); err != nil {
		panic(fmt.Sprintf("bind Cobra flags to Viper: %v", err))
	}

	cmd.AddCommand(newHealthcheckCommand())
	return cmd
}

func newHealthcheckCommand() *cobra.Command {
	var readyFile string
	cmd := &cobra.Command{
		Use:           "healthcheck",
		Short:         "Check whether the guard readiness signal exists",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := os.Stat(readyFile); err != nil {
				return fmt.Errorf("readiness signal %q: %w", readyFile, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&readyFile, "ready-file", "/run/kata-egress-guard/ready", "Path to the readiness signal")
	return cmd
}

func configureLogger(level string) error {
	var parsed slog.Level
	switch strings.ToLower(level) {
	case "debug":
		parsed = slog.LevelDebug
	case "info":
		parsed = slog.LevelInfo
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		return fmt.Errorf("unsupported log level %q", level)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parsed})))
	return nil
}
