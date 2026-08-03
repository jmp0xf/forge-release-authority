# Protected GitHub Actions builder v1

Identity: `https://github.com/jmp0xf/forge-release-authority/blob/main/docs/builders/github-actions-protected-v1.md`

Status: inactive bootstrap contract; no SLSA Build level is claimed.

This document defines the trust boundary and provenance guarantees intended for the protected GitHub Actions mode of
the Forge release authority. The identity names a particular operating mode, not GitHub Actions in general and not an
individual workflow file. It becomes usable only after its workflow and platform controls are installed, reviewed,
and independently verified. The checked-in workflow is initially a non-release canary; its presence alone does not
activate this builder identity.

The current Stage A workflow cannot activate this identity. Its dispatch mode has the single value `canary`; the
finalize, independent-qualification, and protected-attestation jobs each have a checked-in literal-false condition, and
the native jobs create no builder record or uploadable handoff. The sections below define the dormant v1 contract so it
can be reviewed, not behavior that a Stage A run can reach. Activation work must use separately reviewed v2 identities,
policy, records, and verifier rules that reject v1 canary artifacts.

## Scope and trust base

The builder identity represents the transitive closure of entities trusted to execute the
[Forge qualification build type](../build-types/qualify-v1.md) and faithfully create its provenance:

- GitHub's hosted Actions control plane and hosted runner images selected by the five policy-pinned runner labels;
- the immutable owner and repository identities for `jmp0xf/forge-release-authority` (owner ID `2247932`, repository
  ID `1317240187`);
- the protected `main` branch, reviewed authority commit, pinned external actions, authority policy, and independent
  verifier;
- the `forge-release` GitHub Environment and the human owner/legal approval required by ADR-0041;
- GitHub's OIDC issuer `https://token.actions.githubusercontent.com`, the selected keyless attestation service, and
  the transparency log used by that service;
- GitHub's repository, branch, commit, tree, and blob APIs used to resolve protected main commits and source materials;
- the people and platform administrators able to change those controls.

Forge candidate code is deliberately outside the trusted control plane. It is treated as untrusted workload input.
The current single-owner arrangement is accountability, not independent second-person review.

## Permission-separated jobs

This builder mode has four job roles across three non-interchangeable permission domains.

### Native build jobs

Five GitHub-hosted jobs checkout and execute one exact Forge commit for:

```text
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
x86_64-apple-darwin
aarch64-apple-darwin
x86_64-pc-windows-msvc
```

They may read source and upload workflow artifacts. They must not receive an OIDC token, protected environment,
repository secret, attestation permission, GitHub Release permission, or other publication credential. In the dormant
v1 contract each would emit one binary, one SBOM, and one bounded builder record. The current Stage A canary builds the
binary and SBOM only as inputs to its local diagnostic collector; it uploads neither those files nor a builder record.

Each native job provisions the policy-pinned Rust toolchain with both `clippy` and `rustfmt` explicitly installed and
version-probed before candidate execution. The source gates begin with `cargo fmt --all -- --check`; they do not depend
on a component that happens to remain in a hosted runner image. Candidate tests retain their project-native parallel
execution and failure semantics.

For the inactive canary only, each native job writes and uploads one create-only, target-specific v2 runner observation
retained for 30 days. The standard-library-only collector bounds command time and output, file hashing, directory
scans, manifest entries, and final JSON size. It reads only an explicit runner-environment allowlist, replaces known
workspace/tool-cache/home path prefixes, redacts secret-like assignments, hashes bounded regular files, and records
unavailable probes rather than inventing values. It records runner image fields, Rust/Cargo/rustup/Git/Python versions
and executable summaries, target Rust libraries, fresh Cargo registry archives, and available native
compiler/linker/SDK/runtime diagnostics.

Forge also writes one target-specific `forge.release-build-input-observation/v1` file immediately before starting its
Cargo release process. That raw candidate self-report may contain native paths encoded as Base64; Base64 is transport
encoding, not encryption or redaction. It exists only in a fresh `RUNNER_TEMP` directory. After a successful synchronous
`release-build` returns, the authority collector first validates the exact source commit, target, Cargo executable,
ordered 13-argument profile, isolated source and target roots, bounded encodings, and MSVC field shape. It reduces the
values to fixed profiles, entry counts, and ordered path-root classes, removes the raw namespace, and only then performs
the slower outer-runner probes. Ordinary failures run the same fixed cleanup through a Bash `EXIT` trap or PowerShell
`finally`. No upload, cache, handoff, builder record, predicate, or digest includes the raw file or its raw hash.

These observations are produced in the same unprivileged job and operating-system user that executes candidate code.
The source-side facts remain explicitly marked `candidate-controlled-self-report` and
`excluded-from-release-evidence`; the sanitizer constrains disclosure and shape, not truth. The Windows outer-shell
probes remain separate from the candidate-reported classification of Forge's internal bounded MSVC environment. The
observations are never downloaded by finalize, independent qualification, or protected attest, and do not enter the v1
predicate, byproducts, subjects, attestation, or qualified evidence. A forced runner termination may bypass shell
cleanup, so this Stage A design also relies on disposal of the single-use hosted runner and must not be moved to a
persistent self-hosted runner without a stronger trusted cleanup boundary.

### Finalize job

This job is present but mechanically unreachable in Stage A.

The finalize job may execute the candidate's `release-finalize` and `release-check` commands and assemble workflow
artifacts. It has the same unprivileged boundary as native jobs: no OIDC token, protected environment, secret,
attestation permission, or release write. Candidate-generated checks remain useful evidence but are not authority.

### Preflight and independent qualification jobs

The preflight job binds both repositories to their immutable identities and protected public `main` heads before any
candidate execution. After finalization, a separate unprivileged job checks out only the authority repository and
runs the complete verifier over fresh copies of the downloaded files. Neither job receives a secret, OIDC token,
protected environment, attestation permission, or release permission. The independent job's predicate and checksums
are a deterministic preview only: the protected job downloads the original finalized artifacts, reruns the complete
verifier in new private directories, and requires byte-for-byte equality before attestation.
The independent job is present but mechanically unreachable in Stage A.

### Protected attest job

This job is present but mechanically unreachable in Stage A.

Only this job may request an OIDC token and write an attestation. It is gated by the `forge-release` environment and
must require an explicit owner/legal approval in that protected environment. Chat authorization, candidate text, a PR
description, or a passing candidate check is not that approval.

The job runs only for `workflow_dispatch` on `refs/heads/main`. It derives the authority commit from `GITHUB_SHA`,
requires the workflow commit and ref to match the protected `qualify.yml` on `main`, and checks out only that reviewed
authority commit. It runs the authority's standard-library-only verifier over downloaded, finalized bytes in fresh
private directories. The verifier resolves source materials through GitHub's fixed repository-ID commit/tree/blob API
chain; it does not checkout Forge. The job must not run Cargo or xtask, invoke a Forge script, or execute a candidate
binary. Candidate-controlled bytes therefore cannot execute in the process that holds signing identity.

Attestation and release publication are separate authorities. This builder does not create or mutate tags, releases,
or release assets.

## Provenance guarantees

When this identity is active and an invocation succeeds, the protected control plane guarantees:

- `buildDefinition.buildType` is the exact v1 qualification URI;
- `externalParameters` contains only the caller-supplied Forge `sourceCommit`, which must equal the protected Forge
  `main` HEAD resolved by the verifier;
- `internalParameters` is derived from the policy and verifier at the protected authority `main` commit selected by the
  trusted Actions context;
- `resolvedDependencies` contains the exact Forge and authority commits plus SHA-256 descriptors for the
  source-bound `Cargo.lock` and `THIRD-PARTY-LICENSES.txt`;
- the five builder-record byproducts match the frozen runner labels, Rust version, repository identities, commits,
  binary bytes, and SBOM bytes;
- the authority verifier independently accepts the exact thirteen-file set, names, checksums, manifest, SBOM graphs
  and licenses, executable structures, builder records, and source-bound lock/license bytes;
- the enclosing in-toto Statement's subjects come only from the verifier's exact subject-checksum output and contain
  the names and SHA-256 digests of all thirteen finalized files;
- `runDetails.builder.id` is this URI.

The deterministic predicate intentionally omits invocation timestamps and IDs. Empty metadata does not assert that an
invocation lacked timing or platform logs; it means those invocation-specific values are not part of this predicate.

## Tenant-controlled and independently checked data

The requested Forge source commit, binaries, SBOMs, manifest, checksums, license asset, and initial builder records
originate with the tenant or jobs that execute tenant-controlled candidate code. The protected verifier treats those
claims and uploaded bytes as untrusted. It independently resolves the immutable Forge repository ID, protected `main`
HEAD, exact commit/tree, `Cargo.lock`, and `THIRD-PARTY-LICENSES.txt`; there is no fallback to candidate-supplied source
files. It never accepts candidate claims of approval, signature, runner authority, or publication status.

The `subject` field of the final in-toto Statement is produced by the attestation mechanism from the independently
verified checksum list. It is not copied from `release-manifest.json` or from the predicate's internal parameters.

## Signer-builder pairing

Consumers must accept this builder only with the signer identity deployed for this exact authority mode. At minimum,
verification must bind all of the following:

- OIDC issuer `https://token.actions.githubusercontent.com`;
- the immutable authority owner and repository IDs above;
- the reviewed `qualify.yml` workflow on the protected default branch;
- environment `forge-release` and its required approval;
- this exact `builder.id` and build-type URI;
- the expected keyless transparency-log policy.

Activation is deliberately two-stage. The executable-workflow change freezes the intended identity constraints but
leaves the builder inactive. After that change and the hosted controls are merged, a first protected run is a
non-release canary: it must record the actual certificate/workflow identity emitted by the selected attestation action
and verify the bundle cryptographically against the exact repository, workflow, ref, commit, issuer, subject digests,
and GitHub-hosted runner boundary. A follow-up reviewed change must preserve representative signer evidence and add an
automated verifier test for that exact signer-builder pair before any run counts as release qualification. A signer
valid for another repository, workflow, ref, environment, self-hosted mode, or unprotected mode is not valid for this
builder. Conversely, this signer must not attest a different builder identity.

The follow-up freezes stable issuer, certificate, workflow/ref, environment, and immutable repository identity
constraints; it must not turn the canary's authority commit into a permanent signer constant. For each attestation,
the dynamic signer and source commit must instead equal the predicate's `authorityCommit` and the protected authority
`main` commit for that invocation. Canary evidence tests must cover the observed field shape plus positive and negative
signer-builder pairings.

## Operational controls

Before activation, repository evidence must show all of the following:

- branch protection applies to administrators, blocks force-push and deletion, requires pull requests and resolved
  conversations, and binds the required verification checks;
- only allowlisted, full-commit-pinned GitHub Actions can run;
- build and finalize jobs have read-only minimum permissions and no `id-token: write`;
- the attest job alone has the minimum OIDC/attestation permissions and protected environment;
- the environment deployment-branch rule selects only `main`, and administrators cannot bypass its approval;
- every run uses new mode-`0700`, initially empty verifier output directories with no concurrent same-user writer;
- the authority and Forge repository identities, visibility, release immutability, caches, and selected source commit
  are rechecked immediately before qualification or publication.

A local test result or repository document cannot prove these hosted controls. Preserve API/UI evidence for each
release invocation.

## Failures and recovery

Any missing artifact, failed native job, unknown field, policy drift, dependency mismatch, verifier rejection,
environment rejection, signer mismatch, or incomplete attestation fails the invocation. Never reuse a failed output
directory. Do not delete and recreate a tag, release, attestation, or asset to conceal a failed run; start a new
reviewed invocation or, if the candidate changes, a new candidate.

Workflow artifact names are immutable within one run and uploads use `overwrite: false`. Preserve every old attempt
and its evidence. After any failure, approval rejection, or incomplete attestation, do not use GitHub's "re-run all
jobs", "re-run failed jobs", or individual-job controls; start a new workflow dispatch so every handoff has a new run
identity. Intermediate handoffs are retained for 30 days to allow protected-environment review; qualified evidence is
retained for 90 days.

If signer identity, workflow protection, repository ownership, hosted runner trust, or environment enforcement is
uncertain, consumers must treat the builder as unavailable rather than downgrade silently.

## SLSA level and limitations

No SLSA Build level is currently claimed. The repository is still bootstrapping: the executable workflow is
mechanically canary-only, signer-builder verification remains a required follow-up, the environment controls require
final platform verification, and the single-owner topology does not provide independent second-person review. A future
level claim requires separately reviewed v2 identities plus an independent assessment of the deployed platform against
the then-current SLSA requirements; changing this sentence is not such an assessment.

Known scope limits include GitHub-hosted service trust, platform administrators, the approval owner, pinned third-party
attestation infrastructure, and best-effort completeness of dependencies outside the four qualification inputs. The
builder-record byproducts describe selected workload facts; they do not prove the hosted runner image, compiler
wrapper, linker, dependency cache, or every transitive builder dependency unless the deployed workflow records and
verifies them. Before activation, the non-release canary must capture and the v2 follow-up change must freeze or
conservatively verify the effective package sources, compiler/linker and SDK inputs, runtime-library allowlist, runner
image identity, cache/environment behavior, and absence or rejection of unknown path classes observed on all five
native targets.

## Versioning

Changes that preserve this trust boundary and every stated guarantee may update the document in place. Any new mode
with weaker isolation, different signer identity, self-hosted runners, changed permission domains, changed approval
semantics, or incompatible guarantee requires a new builder URI. Consumers must never infer compatibility merely from
a similar workflow filename.
