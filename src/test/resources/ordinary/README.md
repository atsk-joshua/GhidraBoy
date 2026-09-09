# Ordinary regression inputs

Exact retained self-authored fixtures; hashes and historical provenance are in PROVENANCE.json. Finite and isolation tests load classpath resources and require their expected hashes. Missing inputs fail, never skip. A/C and U1/U2 also supply the installed-path capture inputs; the existing inline ordinary/banked/unknown builders remain self-contained and preserve their byte-specific mutation cases. These fixtures are not private ROMs. Test-only execution conditions are not final capability restrictions.

W2e adds `F1234.gb`: eight real MBC5 banks and four distinct selector sources.
Its new identity is recorded separately in `W2e-PROVENANCE.json`; the retained
20-entry `PROVENANCE.json` remains unchanged.
The original four-bank F12/F12_WIDE fixtures and their historical hashes remain
unchanged; bank 4 in that geometry aliases bank 0 and is not the four-distinct-bank
W2e witness. Resource tests derive larger domains from a copy of F1234 solely to
check complete emission/refusal under the operation budget.
