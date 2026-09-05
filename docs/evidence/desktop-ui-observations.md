# Real desktop observations on the development Mac

CUA selected the running Python.app SDL window by the Python framework's application path after the user granted desktop permission. Screenshots in the task show a real 640×576 GBC / SameBoy window with GBW3's title, intro text, and main menu. Pressing Return through CUA changed intro → title → main menu. This exposed and verified the fix retaining short key taps for 30 ms.

The actual SDL probe (no dummy video driver) ran for 120.00014 seconds of wall time and 119.99936 seconds of emulator time. Original ROM/save files were never written. This verifies rendering, basic keyboard input and real-time pacing on macOS arm64; it does not establish Steam Deck desktop usability, held-key release across focus loss, or integrated Ghidra paused-window interaction.

The desktop tool lists the Ghidra/RealTraceTest Java process but rejects it by bundle ID, display name and executable path. A thread dump locates the fresh-profile test at Ghidra's user-agreement dialog. The user was asked to review/accept that dialog; no agreement was bypassed or silently accepted.

Paused-input follow-up: `paused-display.json` records a real CUA Z tap, a real window minimize clearing a guest-held A seeded through the native ABI, and a real close clearing keys. Emulated ticks remained26171648 throughout. The integrated `--display-close` Ghidra test also saved and reopened TERMINATED state after the actual window close. This is Mac evidence; physical held-key behavior on the Steam Deck remains to be checked.
