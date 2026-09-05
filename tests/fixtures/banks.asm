; SPDX-License-Identifier: MIT
; Self-authored debugger fixture. Two ROM banks at $4029; distinct WRAM writers.
SECTION "Interrupt", ROM0[$40]
    reti
SECTION "Entry", ROM0[$100]
    nop
    jp Start
    ds $150-@, 0
SECTION "Main", ROM0[$150]
Start:
    di
    ld sp, $cffe
    xor a
    ldh [$ff40], a
    ld a, 1
    ld [$2000], a
    call $4029
    ld a, 2
    ld [$2000], a
    call $4029
    ld a, 3
    ldh [$ff70], a
    ld a, $35
DirectWriter:
    ld [$d034], a
SameWriter:
    ld [$d034], a
    ld a, $36
ChangedWriter:
    ld [$d034], a
    ld a, 4
    ldh [$ff70], a
    ld a, $47
OtherWriter:
    ld [$d034], a
    xor a
    ldh [$ff70], a
    ld a, $58
    ld [$f034], a
    ld bc, $3456
    ld de, $789a
    ld hl, $12b0
    push hl
    pop af
    ld hl, $bcde
    jp $4567
SECTION "BankOne", ROMX[$4029], BANK[1]
BankOne:
    ld a, $11
    ret
SECTION "BankTwo", ROMX[$4029], BANK[2]
BankTwo:
    ld a, $22
    ret
SECTION "Final", ROMX[$4567], BANK[2]
Final:
    nop
    rlc b
    call Subroutine
    halt
    nop
    stop
    jr Final
Subroutine:
    inc c
    ret
SECTION "Blocked VRAM", ROM0[$300]
BlockedStart:
    di
    ld a, $91
    ldh [$ff40], a
.wait
    ldh a, [$ff41]
    and 3
    cp 3
    jr nz, .wait
    ld a, $77
BlockedWriter:
    ld [$8000], a
BlockedEnd:
    jr BlockedEnd
SECTION "Stop test", ROM0[$350]
StopStart:
    di
    stop
    nop
SECTION "RST vector", ROM0[$28]
    inc e
    ret
SECTION "Conditional calls", ROM0[$380]
ConditionalStart:
    xor a
NotTaken:
    call nz, ConditionalSub
Taken:
    call z, ConditionalSub
RestartCall:
    rst $28
    halt
ConditionalSub:
    inc d
    ret
