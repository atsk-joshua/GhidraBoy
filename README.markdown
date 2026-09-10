# GhidraBoy

Game Boy and Game Boy Color analysis for **Ghidra 12.1.3 / JDK 21**, with an
optional [GhidraBoy debugger](debugger/README.md). This is a development preview;
GUI and release acceptance remain incomplete.

The static extension provides SM83 instruction semantics, cartridge and boot-ROM
loading, banked memory views, hardware registers and data types, symbol import,
ROM export, conservative bank analysis and per-function compiler conventions.
It works without an emulator, Python or SDL. The optional debugger adds live
execution and captured history through SameBoy or the experimental mGBA backend.

![Tetris disassembly](screenshot.png)

Start with [installation and static workflows](docs/user-workflows.md), or the
[debugger overview](debugger/README.md). For supported inputs, analysis assumptions
and compiler conventions, use the [documentation map](docs/README.md).

The [roadmap](docs/roadmap.md) prioritizes complete static analysis: software-call
semantics, bank-dependent memory and flow, discovery, and verified compiler/data
knowledge. The [planned specification](docs/static-analysis-spec.md) and
[research record](docs/static-analysis-research.md) distinguish required work
from current capabilities. Existing integration and release work remains on the
roadmap with updated priorities.

For implementation, start with the [agent handoff](docs/static-analysis-implementation.md):
source targets, first regressions, commands and architecture decision gates.

Contributors and agents should read the [repository working rules](AGENTS.md).
Contributors need this repository and the pinned build dependencies. Follow
[building and packaging](docs/building.md); run `python3 tools/check.py` for the
inexpensive checks. [Validation](docs/validation.md) distinguishes automated tests
from installed, native and GUI qualification.

The experimental stock transport uses `SM83:LE:16:default`, language version 2.0,
and retains compiler `default` and added compiler profiles. Old annotated-Program
upgrade is not qualified; see the [transport decision](docs/decisions/stock-ghidra-transport.md). Preserving
saved Programs is distinct from running on older Ghidra versions: current builds
require 12.1.3. See [instruction compatibility](docs/instruction-compatibility.md)
and [changes since the upstream release](docs/changes-since-official-release-report.md).
Historical upstream binaries remain available from the
[upstream releases](https://github.com/Gekkio/GhidraBoy/releases); use the runtime
required by the particular release.

General bank effects, inferred call signatures and complete semantic decompilation
remain limited; absence of diagnostics is not proof of correct recovered code.
See the [analysis contract](docs/analysis.md) and [debugger support matrix](debugger/docs/SUPPORT.md).

GhidraBoy retains Joonas Javanainen/Gekkio and contributor attribution and is
licensed under Apache 2.0. See [LICENSE](LICENSE) and component notices in LICENSES.
