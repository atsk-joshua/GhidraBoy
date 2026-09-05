# First generic debugging session

Install the package using INSTALL.md. Open Ghidra12.1.3, import the included self-authored teaching.gbc and open its Debugger tool. Enable GbcPlugin if absent, then select the GBC / SameBoy launcher and the teaching ROM. The installed runtime path is supplied by setup.

Use Step Into to inspect the 16-bit PC and register pairs/aliases. ROM banks 1 and 2 execute at the same CPU address0x4029 with different bytes. Select a bank-specific static address, use GBC → Breakpoint in this physical bank, and Resume. Physical ROM/WRAM/VRAM spaces remain available even when a bank is inactive.

GBC History shows completed raw accesses, attempts/final values, writer coordinates and epochs. Select an event and Go to writer to inspect its historical capture and verified static destination. Bookmark observation appends to an existing note. When a static identity is ambiguous, inspect candidate views and explicitly select one for future captures. Existing history and user mappings remain intact.

Save a checkpoint, resume/step, restore and compare epochs and old captured bytes. Historical selection is observational; live actions require the current target/capture. Experiment edits require explicit launch opt-in, paused state and a recovery checkpoint. Missing or failing optional profiles do not prevent generic debugging.

The game window uses arrows, Z/X, Enter and Backspace. Test paused pumping, held-key focus release and clean close using the deferred device checklist. These instructions do not claim that the target window has been validated.
