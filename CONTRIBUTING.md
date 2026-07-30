# Contributing

This repository controls a release trust boundary. Keep changes small, explicit, and independently reviewable.

- Use a pull request for every change after the initial repository bootstrap.
- Pin every external GitHub Action to a full 40-character commit ID.
- Give build jobs read-only permissions and keep publication credentials behind the protected release environment.
- Do not add Forge product code, generated release assets, personal access tokens, private keys, or candidate-owned
  approval policy.
- Add or update deterministic tests for every executable policy change.
- Never replace an existing release asset, reuse a released tag, or weaken a gate to make a candidate pass.

Passing this repository's public tests is necessary but does not replace the protected environment approval or the
platform settings documented by the release runbook.
