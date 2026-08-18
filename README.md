# TDS GA7 Release Gate Policy Service

Deterministic Policy Endpoint for CI Release Metadata (`POST /release-gate`).

## Identity
TDS identity: 24f3005189@ds.study.iitm.ac.in

## Endpoint Rules
- Least privilege permissions: `contents: read`, `packages: write`, `id-token: none`.
- PR trigger: `pull_request` only (`pull_request_target` disallowed).
- Matrix & Tests: `testsPassed: true`, `matrixComplete: true`, `failFast: false`.
- Action pinning: `actions` owned actions may use tags, 3rd party actions require full 40-char SHA.
- Image requirements: `multiStage: true`, `runsAsRoot: false`, `secretMode: none|buildkit`, `criticalVulnerabilities: 0`, `digestPinned: true`.
- Production requirements: `ref: refs/heads/main`, `event: push`, `workflow.environmentApproval: true`.
