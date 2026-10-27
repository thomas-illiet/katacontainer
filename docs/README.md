# Documentation

This documentation describes how `kata-egress-guard` works and how to operate
it on Kubernetes with Kata Containers.

## Guides

- [Architecture](architecture.md) — components, isolation boundaries, and network flows.
- [Security model](security.md) — assumptions, guarantees, and limitations.
- [Policy configuration](policy.md) — allowlist format and examples.
- [Operations](operations.md) — installation, verification, metrics, and incidents.

## Diagrams

- [Kata Pod architecture](diagrams/architecture.svg)
- [Fail-closed startup sequence](diagrams/startup-sequence.svg)
- [Outbound connection decision](diagrams/egress-decision.svg)

The diagrams are standalone SVG files, versioned with the code and readable
without an external generation tool.
