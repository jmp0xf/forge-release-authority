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

The repository is being bootstrapped. It does not yet qualify, attest, tag, upload, or publish Forge releases. The
first executable workflow will be added in a separate reviewed pull request.

The stable provenance identities are documented by the
[Forge qualification build type](docs/build-types/qualify-v1.md) and the
[protected GitHub Actions builder](docs/builders/github-actions-protected-v1.md). These contracts define how to
interpret evidence; they do not by themselves establish a SLSA Build level. This repository claims no SLSA Build
level until the complete platform and signer-builder pair have been independently assessed.

The verifier creates its predicate and subject-checksum outputs without overwriting existing paths. The two files are
not a multi-file transaction: a late write failure can leave one sibling behind. Qualification runs therefore require
an initially empty output directory owned by the verifier user with mode `0700`, and no concurrent process running as
that same user may modify it. Inspect any residue after failure and rerun from a new empty private directory.

The production verifier accepts only finalized asset and builder-record directories plus the requested Forge commit.
It derives the authority commit from an exact protected-main GitHub Actions context, reads policy from its own checkout,
and resolves `Cargo.lock`, `THIRD-PARTY-LICENSES.txt`, policy, and verifier bytes through fixed GitHub repository IDs and
commit/tree/blob objects. It has no path or commit option that can relabel arbitrary local bytes as trusted source.

## Security

Do not disclose vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) to submit a private report.

## License

The policy, workflow, and supporting code in this repository are available under the [MIT License](LICENSE).
