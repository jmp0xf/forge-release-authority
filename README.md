# Forge Release Authority

This repository is the physically separate release authority for
[`jmp0xf/forge`](https://github.com/jmp0xf/forge). It exists so a Forge release candidate cannot change the final
qualification, attestation, approval, publication, or withdrawal rules that judge that same candidate.

## Boundary

- Forge development stays in `jmp0xf/forge`; this repository does not accept product code.
- Authority policy and executable workflows are changed through pull requests to this repository.
- Candidate source is consumed only by an exact 40-character commit ID after it has been reviewed and merged to the
  Forge default branch.
- Build jobs receive no publication credential. Attestation requires a protected environment approval.
- The authority never overwrites an existing tag or release asset and never treats candidate-generated evidence as
  external approval.
- External actions are referenced by full commit ID. Long-lived personal access tokens are not accepted as release
  credentials.

## Status

The repository is being bootstrapped. `.github/workflows/qualify.yml` is mechanically restricted to its required
`mode=canary` choice. It runs preflight plus the five unprivileged native jobs, uploads only one sanitized runner
observation per target, and keeps finalize, independent qualification, protected attestation, and every native handoff
unreachable. Their dormant definitions remain visible for review, but each downstream job has a repository-controlled
literal-false condition. This revision cannot qualify, attest, tag, upload, or publish a Forge release.

Each native job asks Forge to write its candidate-controlled build-input observation into a fresh private
`RUNNER_TEMP` namespace. The authority consumes that file as the first operation after a successful synchronous
`release-build`, validates a strict bounded contract, reduces native values to fixed profiles, counts, and path classes,
then deletes the raw namespace before running the slower outer-runner probes. The raw JSON and its Base64-encoded native
values are never uploaded, cached, hashed into evidence, or treated as encryption. The resulting v2 runner observation
is an untrusted bootstrap diagnostic, not a builder record, provenance byproduct, protected-job input, approval, or
release evidence.

This cleanup covers ordinary command and validation failures. A force-killed job may bypass shell cleanup, so the
current boundary also depends on disposal of the single-use GitHub-hosted runner. Candidate code and the sanitizer run
as the same runner user; candidate code can falsify, race, or tamper with its self-report. Sanitization limits
disclosure and diagnostic shape, not candidate authority. Before any later release mode is activated, the observed
stable inputs and signer-builder identity must be frozen or conservatively verified in a separately reviewed v2 policy
and verifier change.

The stable provenance identities are documented by the
[Forge qualification build type](docs/build-types/qualify-v1.md) and the
[protected GitHub Actions builder](docs/builders/github-actions-protected-v1.md). These contracts define how to
interpret evidence; they do not by themselves establish a SLSA Build level. This repository claims no SLSA Build
level until the complete platform and signer-builder pair have been independently assessed.

The verifier creates its predicate and subject-checksum outputs without overwriting existing paths. The two files are
not a multi-file transaction: a late write failure can leave one sibling behind. Qualification runs therefore require
an initially empty output directory owned by the verifier user with mode `0700`, and no concurrent process running as
that same user may modify it. For a direct verifier invocation, inspect any residue after failure and rerun from a new
empty private directory. A failed, rejected, or incomplete GitHub workflow attempt instead requires a fresh
`workflow_dispatch`; do not use GitHub's job or run re-run controls.

The production verifier accepts only finalized asset and builder-record directories plus the requested Forge commit.
It derives the authority commit from an exact protected-main GitHub Actions context, reads policy from its own checkout,
and resolves `Cargo.lock`, `THIRD-PARTY-LICENSES.txt`, policy, and verifier bytes through fixed GitHub repository IDs and
commit/tree/blob objects. It has no path or commit option that can relabel arbitrary local bytes as trusted source.

## Security

Do not disclose vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) to submit a private report.

## License

The policy, workflow, and supporting code in this repository are available under the [MIT License](LICENSE).
