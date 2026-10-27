# Policy configuration

## Helm format

Each rule contains at least one CIDR, one protocol, and one port:

```yaml
policy:
  egress:
    - cidrs:
        - 10.20.0.0/16
        - 2001:db8:20::/48
      protocol: TCP
      ports: [443]
    - cidrs:
        - 10.96.0.10/32
      protocol: UDP
      ports: [53]
```

Constraints:

- `protocol` is exactly `TCP` or `UDP`;
- every port is between 1 and 65535;
- every destination is an IPv4 or IPv6 CIDR;
- `egress`, `cidrs`, and `ports` cannot be empty;
- duplicate rules are normalized by the agent;
- host bits in a CIDR are masked before insertion.

## DNS

Allowing port 53 is not enough: the DNS server CIDR must also be present. For a
`kube-dns` Service, use its `ClusterIP` as `/32` or `/128`. DNS-over-TLS and
DNS-over-HTTPS require their own TCP destinations.

A DNS response may contain multiple addresses that change over time. Version 1
does not update maps dynamically: anticipate all required addresses or redeploy
the Pod with a new policy.

## Package registries and Git

A development session commonly needs several destinations:

```yaml
policy:
  egress:
    # Cluster DNS
    - cidrs: ["10.96.0.10/32"]
      protocol: UDP
      ports: [53]
    # Internal HTTPS proxy or mirror
    - cidrs: ["10.30.12.15/32"]
      protocol: TCP
      ports: [443]
    # Internal Git over SSH
    - cidrs: ["10.40.0.0/24"]
      protocol: TCP
      ports: [22]
```

Prefer controlled internal proxies or mirrors over broad public ranges that may
host multiple tenants.

## Applying a change

Maps are immutable. A Helm change produces a new template checksum and triggers
a rollout:

```sh
helm upgrade code-workspace charts/kata-egress-guard \
  --values production-values.yaml
kubectl rollout status deployment/code-workspace-kata-egress-guard
```
