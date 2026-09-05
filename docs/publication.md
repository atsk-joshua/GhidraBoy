# Publication is a separate authorized action

Component CI builds and tests with read-only repository permissions. It no longer creates a draft release automatically when a tag appears. Publication requires a separate explicit operator authorization and review of the exact source/artifact/acceptance tuple. This local integration task neither creates tags nor publishes releases.

Before any authorized release, verify candidate SHA256SUMS, dependency/source manifests, required acceptance logs, limits and license inventory. Use a distinct publication workflow or operator action with the minimal required token scope. Do not execute untrusted PR checkout code with release credentials. Private-repository build attestations depend on hosting plan support and are not a functional acceptance substitute.
