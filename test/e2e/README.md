# Kata end-to-end acceptance

Run these checks only on a disposable Kubernetes cluster with a functional Kata
RuntimeClass and a guest kernel that satisfies the prerequisites in the root
README. The test deliberately attempts prohibited network access from the
code-server terminal.

1. Build and push `kata-egress-guard` by digest.
2. Create the password secret and install the chart with `production=true`.
3. Verify an allowlisted TCP and UDP destination from the terminal.
4. Verify non-allowlisted IPv4, IPv6, ICMP and raw sockets fail.
5. Connect to code-server through its Service and verify responses succeed.
6. Scrape `/metrics` and verify the denied counters increase.
7. Install a policy with an invalid CIDR and verify Helm rejects it.
8. Use a guest without a required cgroup hook and verify code-server never
   becomes ready.
