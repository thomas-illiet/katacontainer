# Kata egress guard

`kata-egress-guard` runs a rootless code-server workload in a Kata Containers
sandbox and enforces an immutable, destination-based egress allowlist in the
Kata guest kernel. It does not rely on the host kernel seeing individual
container sockets.

Detailed documentation, including architecture and flow diagrams, is available
in [`docs/`](docs/README.md).

The guard attaches cgroup eBPF programs for IPv4/IPv6 TCP `connect`, UDP
`connect`/`sendmsg`, and Internet socket creation. TCP responses on accepted
code-server connections remain valid because the policy controls connections
initiated by the Pod rather than every response packet. AF_UNIX and loopback
remain available. ICMP, raw sockets, SCTP, and other Internet protocols are
denied.

## Security model

- The guard discovers the Pod cgroup from its own cgroup-v2 membership and the
  Kubernetes Pod UID. It refuses ambiguous or missing matches.
- The policy maps are frozen before five links are attached and pinned. The
  readiness file is published only after every attachment succeeds.
- code-server waits for that file, runs as a non-zero UID/GID, has no Linux
  capabilities, cannot gain privileges, and uses a read-only root filesystem.
- The guard starts privileged inside the Kata guest because loading and pinning
  BPF requires it. Once attached it sets `no_new_privs`, removes supplementary
  groups, and changes permanently to UID/GID 65532.
- A pre-existing pin directory is never removed or replaced. This prevents an
  agent restart from intentionally detaching a potentially active policy. If
  the agent restarts, recreate the Pod; the Pod is marked unready meanwhile.
- DNS and the Kubernetes API have no implicit exception. Add every required
  service IP, protocol, and port to the allowlist.

This is one layer of a multi-tenant design, not a complete sandbox. The chart
also emits a matching Kubernetes NetworkPolicy when enabled, but that policy is
only defense in depth and depends on the cluster CNI.

## Prerequisites

The Kata guest, not only the Kubernetes node, must provide:

- a unified cgroup v2 hierarchy visible at `/sys/fs/cgroup`;
- `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, cgroup BPF and BTF support;
- a mounted bpffs at `/sys/fs/bpf` shared for the lifetime of the sandbox;
- cgroup hooks for IPv4/IPv6 connect, UDP sendmsg, and socket creation.

Use a Kata `runtime-rs` RuntimeClass. Configure containerd or CRI-O with
`privileged_without_host_devices=true` for the Kata runtime. The guard is
privileged only inside the guest; do not expose host devices to it. See Kata's
[privileged container guidance](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/privileged.md).

The guard container uses an unconfined seccomp profile during BPF installation
because generic RuntimeDefault profiles commonly reject the BPF syscall. It
drops its process credentials immediately after installation. code-server
retains `RuntimeDefault`.

## Build and test

The bytecode is generated inside Linux so builds work from macOS as well:

```sh
make test
make coverage
make helm-lint
make build
```

The Docker build compiles both the eBPF object and a static Go binary. CI builds
multi-architecture images with provenance and SBOM attestations and signs pushed
digests with Cosign. CI enforces 100% statement coverage for all maintained
business-logic packages under `internal/...`. Generated `bpf2go` bindings and
privileged guest-kernel attachment paths are verified by Linux compilation and
Kata integration tests instead of being counted as unit coverage. Kernel/Kata
acceptance scenarios are documented in
[`test/e2e/README.md`](test/e2e/README.md).

## Install

Create the code-server password without placing it in Helm values:

```sh
kubectl create secret generic code-server-auth \
  --from-literal=password='replace-with-a-long-random-password'
```

Create a production values file. Images must be pinned by digest whenever
`production: true`:

```yaml
production: true
runtimeClassName: kata-qemu-runtime-rs

guard:
  image:
    repository: ghcr.io/your-org/kata-egress-guard
    digest: sha256:REPLACE_WITH_64_HEX_CHARACTERS

codeServer:
  image:
    repository: ghcr.io/coder/code-server
    digest: sha256:REPLACE_WITH_64_HEX_CHARACTERS
  existingSecret: code-server-auth

policy:
  egress:
    - cidrs: ["10.20.0.0/16", "2001:db8:20::/48"]
      protocol: TCP
      ports: [443]
    - cidrs: ["10.96.0.10/32"]
      protocol: UDP
      ports: [53]
```

Then install and wait for both containers:

```sh
helm upgrade --install code-workspace charts/kata-egress-guard \
  --values production-values.yaml
kubectl rollout status deployment/code-workspace-kata-egress-guard
```

Changing `policy.egress` changes a checksum on the Pod template and therefore
creates a new Kata sandbox. Existing Pods retain their frozen policy until
termination.

## Metrics

By default the guard serves metrics only on `127.0.0.1:9090`. Enabling
`serviceMonitor.enabled` binds the endpoint to the Pod interface, adds a Service
port and creates a Prometheus Operator ServiceMonitor.

The collector exposes:

- `kata_egress_guard_attached`;
- `kata_egress_guard_events_total{result="allowed|denied|denied_ipv4|denied_ipv6|denied_protocol|lookup_error"}`.

## Operational limitations

- Rules are CIDR, protocol, and destination-port based. DNS names are not
  resolved dynamically.
- UDP receive traffic is not independently filtered; the initiating send is.
- Policy replacement in place is intentionally unsupported. Use a rollout.
- A real Kata cluster is required to validate guest-kernel hooks. A Docker
  build proves compilation, not runtime compatibility with a particular guest.
