# Forge qualification build type v1

Identity: `https://github.com/jmp0xf/forge-release-authority/blob/main/docs/build-types/qualify-v1.md`

Status: inactive bootstrap contract; the executable workflow is mechanically restricted to a non-release canary, and
activation requires separately reviewed v2 identities and verifier rules.

This document defines the `buildType` used by the Forge release authority's deterministic
[SLSA Provenance v1](https://slsa.dev/spec/v1.2/build-provenance) predicate. It defines how one exact Forge source
commit is built, finalized, independently qualified, and converted into a thirteen-subject attestation. It does not
claim a SLSA Build level.

## Invocation

The dormant v1 build type has one external parameter:

```json
{"sourceCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

`sourceCommit` must be exactly 40 lowercase hexadecimal characters and must equal the protected Forge `main` HEAD
resolved by the authority at qualification time. No tag, version, target, feature, command, environment, repository,
path, or free-form build flag is part of a v1 invocation.

The current Stage A `.github/workflows/qualify.yml` is not a v1 invocation. Its manual dispatch accepts exactly
`sourceCommit` plus a required single-choice diagnostic selector:

```json
{"mode":"canary","sourceCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

`mode` has no `qualification` option or default. Preflight rejects any value other than `canary`, native jobs require
that value, and finalize, independent qualification, and protected attestation each have a repository-controlled
literal-false condition. Therefore `mode` never enters v1 `externalParameters`: Stage A cannot create a v1 predicate or
attestation at all.

The successful invocation is restricted to `refs/heads/main` in the authority repository. The verifier derives
`authorityCommit` from `GITHUB_SHA`, requires `GITHUB_WORKFLOW_SHA` to equal it, and validates the immutable authority
owner/repository IDs and exact `qualify.yml@refs/heads/main` workflow ref. Everything else is selected by that
authority commit and its checked-in `contracts/release-policy.json`. Values derived from source files are dependencies,
not additional external parameters.

## Build definition schema

The predicate's `buildDefinition` has exactly these fields:

```text
buildType
externalParameters
internalParameters
resolvedDependencies
```

### External parameters

`externalParameters` is exactly:

```json
{"sourceCommit":"<40-lowercase-hex>"}
```

Unknown or missing fields are rejected.

### Internal parameters

`internalParameters` is selected and verified by the authority and has exactly this shape:

```json
{
  "authority": {
    "environment": "forge-release",
    "oidcIssuer": "https://token.actions.githubusercontent.com",
    "oidcSubjectPrefix": "repo:jmp0xf@2247932/forge-release-authority@1317240187",
    "ownerId": 2247932,
    "repositoryId": 1317240187
  },
  "authorityCommit": "<40-lowercase-hex>",
  "policySha256": "<64-lowercase-hex>",
  "release": {
    "subjectNames": ["<the sorted exact thirteen names>"],
    "tag": "v0.1.0-rc.2",
    "targets": ["<the exact five target triples in policy order>"],
    "version": "0.1.0-rc.2"
  }
}
```

`subjectNames` freezes the expected names. Subject digests and sizes do not appear in `internalParameters`; those are
output observations, not build inputs. The enclosing in-toto Statement obtains the subject names and SHA-256 digests
from the verifier's separate `subject-checksums` output.

### Resolved dependencies

`resolvedDependencies` is an unordered collection of exactly four ResourceDescriptors:

1. The Forge repository at `sourceCommit`, identified by its `gitCommit` digest.
2. The authority repository at `authorityCommit`, identified by its `gitCommit` digest.
3. `Cargo.lock` at `sourceCommit`, identified by a commit-pinned GitHub blob URI, name, and SHA-256.
4. `THIRD-PARTY-LICENSES.txt` at `sourceCommit`, identified by a commit-pinned GitHub blob URI, name, and SHA-256.

The two file descriptors intentionally omit `length`: `length` is not a standard SLSA ResourceDescriptor field. A
consumer must compare dependencies by URI, not array position.

## Run details and byproducts

`runDetails.builder.id` is the
[protected GitHub Actions builder identity](../builders/github-actions-protected-v1.md). `metadata` is empty in this
deterministic predicate. SLSA permits invocation IDs and timestamps in `runDetails.metadata`; if later added, they must
describe the actual invocation and must not be fabricated or reused.

`runDetails.byproducts` contains the five target-specific builder records, sorted by name. Each descriptor contains
only `name` and a SHA-256 digest. They are diagnostic records, not release subjects or external approvals.

While this build type remains inactive, each native workflow job uploads one target-specific v2 canary runner
observation. Forge's raw build-input self-report stays in a private runner-temporary namespace; the authority validates
and reduces it to fixed profiles, counts, and path classes, then deletes it before slower runner probes. The raw file,
its Base64 native values, and its raw hash are never uploaded. The sanitized summary remains candidate-controlled and
excluded from release evidence.

These temporary artifacts are bootstrap diagnostics outside this v1 build-type schema: they are not builder records,
`runDetails.byproducts`, subjects, verifier inputs, or protected-attest inputs. A later reviewed v2 change must decide
which observed stable constraints to freeze or conservatively verify and must reject all v1 canary identities; merely
uploading the observations does not change this contract or qualify a release.

## Process

If implemented by a future reviewed authority, the dormant build type consists of these fail-closed stages. None after
native canary observation is reachable in Stage A:

1. Reject any invocation outside the protected authority `main` ref, derive the authority commit from the trusted
   Actions context, and require the caller's Forge commit to equal the protected Forge `main` HEAD. The five native
   build jobs checkout that Forge commit and run on the runner labels and Rust version selected by policy. These jobs
   have no OIDC token, protected environment, secret, attestation permission, or release permission.
2. Each native job produces one target binary, one CycloneDX 1.6 SBOM, and one builder record. The two Linux binaries
   are static musl executables. No cross-built artifact may substitute for a required native target.
3. An unprivileged finalize job runs the candidate's local finalization and checks, copies the source-bound
   `THIRD-PARTY-LICENSES.txt`, and assembles exactly thirteen final files. It has no OIDC token, protected environment,
   or publication permission.
4. An independent unprivileged job checks out only the authority repository and runs the same verifier over fresh
   copies of the finalized bytes. Its deterministic outputs are a preview, not signing authority, and are not trusted
   by the protected job.
5. The protected job checks out only the authority repository. Its standard-library-only verifier uses the GitHub Git
   Data API at fixed numeric repository identities to resolve each exact commit, tree, and regular blob. It rejects
   redirects, mutable refs, symlinks, submodules, executable source-material modes, identity drift, truncation, digest
   mismatch, or resource-limit violations. It fetches `Cargo.lock` and `THIRD-PARTY-LICENSES.txt` itself, and verifies
   that the running policy and verifier bytes match the protected authority commit. It does not import Forge code, run
   Cargo or xtask, or execute candidate binaries. It then independently verifies the exact file sets, manifest,
   checksums, SBOM graph and licenses, native executable structures, and builder records.
6. The verifier emits a deterministic predicate plus checksums for all thirteen subjects. A pinned attestation action
   may wrap them in an in-toto Statement only after protected-environment approval. Publication is a later,
   create-only operation and is not part of this build type.

Any missing capability, unknown field, unexpected file, identity drift, checksum mismatch, structure mismatch,
resource-limit violation, output collision, or partial write fails the invocation. A failed run is never approval.
Because workflow artifact uploads are create-only, any failed, rejected, or incomplete workflow attempt requires a
fresh `workflow_dispatch`. GitHub's re-run controls do not create a new reviewed invocation and must not be used.

## Subjects

The enclosing in-toto Statement must contain exactly these thirteen basenames, each with its actual SHA-256:

```text
SHA256SUMS
THIRD-PARTY-LICENSES.txt
forge-0.1.0-rc.2-aarch64-apple-darwin
forge-0.1.0-rc.2-aarch64-apple-darwin.cdx.json
forge-0.1.0-rc.2-aarch64-unknown-linux-musl
forge-0.1.0-rc.2-aarch64-unknown-linux-musl.cdx.json
forge-0.1.0-rc.2-x86_64-apple-darwin
forge-0.1.0-rc.2-x86_64-apple-darwin.cdx.json
forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe
forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe.cdx.json
forge-0.1.0-rc.2-x86_64-unknown-linux-musl
forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json
release-manifest.json
```

The predicate alone is not an attestation and does not carry the Statement subjects. Standard in-toto v1
ResourceDescriptors have no `length` field. Qualification still verifies actual byte lengths, manifest lengths, and
resource limits before producing the checksum input; it does not invent a non-standard subject field.

## Resource and filesystem limits

The v1 verifier applies these policy limits before semantic parsing:

| Input | Limit |
|---|---:|
| One binary | 64 MiB |
| `Cargo.lock` | 1 MiB |
| One SBOM | 2 MiB |
| License notices | 8 MiB |
| Release manifest | 64 KiB |
| Checksums | 16 KiB |
| One builder record | 64 KiB |
| All release assets | 192 MiB |
| All builder records | 256 KiB |

It additionally caps an SBOM at 512 components and 4,096 dependency edges, ELF at 128 program headers and 1 MiB of
dynamic tables, Mach-O at 256 load commands and 1 MiB of load-command bytes, and PE at 96 sections. Directory
enumeration is bounded by the exact expected file count. JSON integers are bounded before conversion. GitHub API JSON,
tree entry counts, decoded blob sizes, redirects, object modes, and commit/tree/blob identities are also bounded and
validated; an unavailable or inconsistent API has no candidate-file fallback.

Qualification output directories must initially be empty, owned by the verifier user, and mode `0700`. No concurrent
process running as that user may modify them. Outputs are create-only. Because two filesystem names cannot be committed
as one portable transaction, a late failure may leave one sibling; discard the whole private directory and rerun in a
new one.

## Complete example predicate

The following is structurally complete. Repeated hexadecimal characters are illustrative, not release evidence.

```json
{
  "buildDefinition": {
    "buildType": "https://github.com/jmp0xf/forge-release-authority/blob/main/docs/build-types/qualify-v1.md",
    "externalParameters": {
      "sourceCommit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "internalParameters": {
      "authority": {
        "environment": "forge-release",
        "oidcIssuer": "https://token.actions.githubusercontent.com",
        "oidcSubjectPrefix": "repo:jmp0xf@2247932/forge-release-authority@1317240187",
        "ownerId": 2247932,
        "repositoryId": 1317240187
      },
      "authorityCommit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "policySha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "release": {
        "subjectNames": [
          "SHA256SUMS",
          "THIRD-PARTY-LICENSES.txt",
          "forge-0.1.0-rc.2-aarch64-apple-darwin",
          "forge-0.1.0-rc.2-aarch64-apple-darwin.cdx.json",
          "forge-0.1.0-rc.2-aarch64-unknown-linux-musl",
          "forge-0.1.0-rc.2-aarch64-unknown-linux-musl.cdx.json",
          "forge-0.1.0-rc.2-x86_64-apple-darwin",
          "forge-0.1.0-rc.2-x86_64-apple-darwin.cdx.json",
          "forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe",
          "forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe.cdx.json",
          "forge-0.1.0-rc.2-x86_64-unknown-linux-musl",
          "forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json",
          "release-manifest.json"
        ],
        "tag": "v0.1.0-rc.2",
        "targets": [
          "x86_64-unknown-linux-musl",
          "aarch64-unknown-linux-musl",
          "x86_64-apple-darwin",
          "aarch64-apple-darwin",
          "x86_64-pc-windows-msvc"
        ],
        "version": "0.1.0-rc.2"
      }
    },
    "resolvedDependencies": [
      {
        "digest": {"gitCommit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "uri": "git+https://github.com/jmp0xf/forge.git@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      {
        "digest": {"gitCommit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "uri": "git+https://github.com/jmp0xf/forge-release-authority.git@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      },
      {
        "digest": {"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
        "name": "Cargo.lock",
        "uri": "https://github.com/jmp0xf/forge/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Cargo.lock"
      },
      {
        "digest": {"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
        "name": "THIRD-PARTY-LICENSES.txt",
        "uri": "https://github.com/jmp0xf/forge/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/THIRD-PARTY-LICENSES.txt"
      }
    ]
  },
  "runDetails": {
    "builder": {
      "id": "https://github.com/jmp0xf/forge-release-authority/blob/main/docs/builders/github-actions-protected-v1.md"
    },
    "byproducts": [
      {"digest":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"name":"builder-record-aarch64-apple-darwin.json"},
      {"digest":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222"},"name":"builder-record-aarch64-unknown-linux-musl.json"},
      {"digest":{"sha256":"3333333333333333333333333333333333333333333333333333333333333333"},"name":"builder-record-x86_64-apple-darwin.json"},
      {"digest":{"sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"name":"builder-record-x86_64-pc-windows-msvc.json"},
      {"digest":{"sha256":"5555555555555555555555555555555555555555555555555555555555555555"},"name":"builder-record-x86_64-unknown-linux-musl.json"}
    ],
    "metadata": {}
  }
}
```

## Versioning and limitations

Changes that preserve every v1 field's meaning may update this document in place. Any incompatible schema, process,
trust-boundary, or interpretation change requires a new build-type URI. The policy and verifier reject unknown v1
fields even though general SLSA consumers may ignore extensions.

This contract does not prove that GitHub Actions, the protected environment, signer identity, branch protection, or
workflow implementation satisfies a SLSA level. Those are properties of the builder and its deployed controls, not of
this predicate shape. Until that platform is independently assessed, no SLSA Build level is claimed.
