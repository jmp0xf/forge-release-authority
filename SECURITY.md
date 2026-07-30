# Security policy

Do not disclose a suspected vulnerability in a public issue or pull request. Submit it through GitHub's
[private vulnerability reporting form](https://github.com/jmp0xf/forge-release-authority/security/advisories/new).

`jmp0xf` is the temporary triage owner. No response-time SLA is promised. Reports should include the affected policy,
workflow run, commit, artifact, or attestation identity when known, plus reproduction steps that do not contain live
credentials.

This repository protects release policy; it is not a sandbox for untrusted candidate code. Candidate builds run with
read-only repository permissions and without publication credentials. A protected environment gates attestation and
publication authority.
