# Repository ownership

GhidraBoy owns general Game Boy/Game Boy Color tooling: static analysis, the
optional GhidraBoy debugger, emulator adapters, public profile APIs, installers,
self-authored regressions and supporting documentation. It builds independently.
Game-specific conventions, annotated inputs and private research belong outside
this repository and are not generic build or release requirements.

Keep the upstream root layout: src/, data/, ghidra_scripts/ and the root Gradle
build. Optional runtime code lives under debugger/. Reusable generic tests and
qualification tools stay with their implementation.

The standalone debugger checkout and old game-command delegates are retired.
Installed identifiers and saved-work readers remain supported compatibility
surfaces; see [the identity inventory](debugger-identities.md). Historical plans
are retained observations and do not supersede the current documentation map.
