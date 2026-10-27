# Operations

## Cluster preflight

Verify the RuntimeClass and Kata configuration before deployment:

```sh
kubectl get runtimeclass kata-qemu-runtime-rs
kubectl get nodes -o wide
```

The Kata guest must provide:

- cgroup v2 mounted at `/sys/fs/cgroup`;
- bpffs mounted at `/sys/fs/bpf`;
- BTF and the BPF syscall;
- cgroup hooks for `connect4/6`, `sendmsg4/6`, and `sock_create`.

Set `privileged_without_host_devices=true` for the Kata runtime. A Pod that
remains unready with a verifier or attachment error usually indicates an
incompatible guest kernel.

## Installation

```sh
kubectl create secret generic code-server-auth \
  --from-literal=password='replace-with-a-long-random-password'

helm upgrade --install code-workspace charts/kata-egress-guard \
  --values production-values.yaml
```

With `production: true`, both the guard and code-server images must use SHA-256
digests.

## Verification

```sh
kubectl rollout status deployment/code-workspace-kata-egress-guard
kubectl get pods -l app.kubernetes.io/instance=code-workspace
kubectl logs deployment/code-workspace-kata-egress-guard -c guard
```

The structured `egress guard active` log records the cgroup and loaded rule
count. From the code-server terminal, test one allowed and one denied
destination, then confirm that the counters increase.

## Configuration precedence

The agent uses Cobra for its command-line interface and Viper for configuration.
Flags take precedence over environment variables. Environment variables use the
`KATA_EGRESS_GUARD_` prefix and replace dashes with underscores, for example:

```text
--log-level=debug             KATA_EGRESS_GUARD_LOG_LEVEL=debug
--listen=127.0.0.1:9090      KATA_EGRESS_GUARD_LISTEN=127.0.0.1:9090
--pod-uid=<uid>               KATA_EGRESS_GUARD_POD_UID=<uid>
```

Logs are emitted as JSON through the standard library `log/slog` package.

## Test coverage

Run the enforced coverage gate with:

```sh
make coverage
```

The gate requires exactly 100% statement coverage for every maintained package
under `internal/...`. Generated `bpf2go` bindings and privileged kernel
attachment paths are validated through Linux builds and Kata end-to-end tests;
they are intentionally outside the unit-coverage denominator.

## Metrics

By default, `/metrics` listens only on `127.0.0.1:9090`. With
`serviceMonitor.enabled=true`, the chart exposes the port on the Pod interface
and creates a `ServiceMonitor`.

| Metric | Meaning |
|---|---|
| `kata_egress_guard_attached` | Agent is active with links attached |
| `kata_egress_guard_events_total{result="allowed"}` | Allowed decisions |
| `kata_egress_guard_events_total{result="denied"}` | Total denied decisions |
| `...{result="denied_ipv4"}` | Denied IPv4 destinations |
| `...{result="denied_ipv6"}` | Denied IPv6 destinations |
| `...{result="denied_protocol"}` | Denied protocols or socket types |

Recommended alerts:

- Pod unready for more than five minutes;
- `kata_egress_guard_attached != 1`;
- abnormal increase in the denial rate;
- restart of the `guard` container.

## Troubleshooting

### code-server waits indefinitely

Inspect the guard's structured logs. Do not bypass the `ready` file wait: this
is the intended fail-closed behavior. Fix the policy, cgroup, or guest kernel,
then recreate the Pod.

### `pin directory already exists`

The agent restarted after attaching a policy. It refuses to replace pins to
avoid an unfiltered window. Recreate the Pod and its Kata VM:

```sh
kubectl rollout restart deployment/code-workspace-kata-egress-guard
```

### An allowed destination fails

Check the resolved CIDR, address family, protocol, port, and then the
`NetworkPolicy`. An eBPF allow decision cannot override a CNI or external
firewall denial.

### Helm accepts an invalid policy

The JSON Schema checks structure and common CIDR forms. The agent performs a
second strict validation with Go's IP library and fails closed before attachment
if a value is still invalid.
