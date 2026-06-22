# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **yasindce1998@gmail.com** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You should receive an acknowledgment within 72 hours. We will work with you to understand the issue and coordinate a fix.

## Scope

The following are considered security issues:

- **BPF policy bypass** — an agent process evading enforcement
- **Allowlist escape** — unauthorized PIDs gaining allowlist status
- **Generation tag manipulation** — forging or replaying stale generation stamps
- **Privilege escalation** — gaining capabilities through NeuronTrace's BPF programs
- **Ring buffer injection** — spoofing violation events to mislead the controller

The following are **not** in scope:

- Denial-of-service against the NeuronTrace controller process itself (it runs as root — if you have root, you already win)
- Issues that require `CAP_BPF` or root to exploit (the attacker already has kernel access)
- Policy misconfiguration by the user (that's a documentation issue, not a vulnerability)

## Disclosure Timeline

We follow a 90-day coordinated disclosure process:

1. Reporter sends vulnerability details via email
2. We acknowledge within 72 hours
3. We develop and test a fix
4. We release the fix and publish an advisory
5. Reporter may publicly disclose after 90 days, or earlier if the fix is released

## Security Design

NeuronTrace's trust model is documented in [docs/architecture.md](docs/architecture.md#security-model).
