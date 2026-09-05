;--------------------------------------------------------
; File Created by SDCC : free open source ISO C Compiler
; Version 4.5.1 #15267 (Mac OS X ppc)
;--------------------------------------------------------
	.module abi
	
	.optsdcc -msm83 sdcccall(1)
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _mixed2
	.globl _caller
	.globl _pointer
	.globl _mixed
	.globl _current32
	.globl _current16
	.globl _current8
	.globl _legacy32
	.globl _legacy16
	.globl _legacy8
	.globl _sink32
	.globl _sink16
	.globl _sink8
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
	.area _HRAM
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
_sink8::
	.ds 1
_sink16::
	.ds 2
_sink32::
	.ds 4
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
;src/test/resources/compiler/abi.c:8: u8 legacy8(u8 a, u8 b, u8 c) __sdcccall(0) { return a + b + c; }
;	---------------------------------
; Function legacy8
; ---------------------------------
_legacy8::
	ldhl	sp,	#2
	ld	a, (hl+)
	add	a, (hl)
	inc	hl
	add	a, (hl)
	ld	e, a
	ret
;src/test/resources/compiler/abi.c:9: u16 legacy16(u16 a, u16 b, u8 c) __sdcccall(0) { return a + b + c; }
;	---------------------------------
; Function legacy16
; ---------------------------------
_legacy16::
	ldhl	sp,#2
	ld	a, (hl+)
	ld	e, a
	ld	a, (hl+)
	ld	d, a
	ld	a,	(hl+)
	ld	h, (hl)
	ld	l, a
	add	hl, de
	ld	c, l
	ld	b, h
	ldhl	sp,	#6
	ld	l, (hl)
	ld	h, #0x00
	add	hl, bc
	ld	e, l
	ld	d, h
	ret
;src/test/resources/compiler/abi.c:10: u32 legacy32(u32 a) __sdcccall(0) { return a + 1; }
;	---------------------------------
; Function legacy32
; ---------------------------------
_legacy32::
	add	sp, #-4
	ldhl	sp,#6
	ld	a, (hl+)
	ld	e, a
	ld	d, (hl)
	ld	a, e
	add	a, #0x01
	ld	e, a
	ld	a, d
	adc	a, #0x00
	push	af
	ldhl	sp,	#3
	ld	(hl-), a
	ld	(hl), e
	ldhl	sp,#10
	ld	a, (hl+)
	ld	e, a
	ld	d, (hl)
	pop	af
	ld	a, e
	adc	a, #0x00
	ld	e, a
	ld	a, d
	adc	a, #0x00
	ldhl	sp,	#3
	ld	(hl-), a
	ld	(hl), e
	pop	de
	push	de
	ld	a, (hl+)
	ld	h, (hl)
	ld	l, a
	add	sp, #4
	ret
;src/test/resources/compiler/abi.c:11: u8 current8(u8 a, u8 b, u8 c) __sdcccall(1) { return a + b + c; }
;	---------------------------------
; Function current8
; ---------------------------------
_current8::
	add	a, e
	ldhl	sp,	#2
	add	a, (hl)
	pop	hl
	inc	sp
	jp	(hl)
;src/test/resources/compiler/abi.c:12: u16 current16(u16 a, u16 b, u8 c) __sdcccall(1) { return a + b + c; }
;	---------------------------------
; Function current16
; ---------------------------------
_current16::
	ld	l, c
	ld	h, b
	add	hl, de
	ld	c, l
	ld	b, h
	ldhl	sp,	#2
	ld	a, (hl)
	ld	l, a
	ld	h, #0x00
	add	hl, bc
	ld	c, l
	ld	b, h
	pop	hl
	inc	sp
	jp	(hl)
;src/test/resources/compiler/abi.c:13: u32 current32(u32 a) __sdcccall(1) { return a + 1; }
;	---------------------------------
; Function current32
; ---------------------------------
_current32::
	ld	l, e
	ld	h, d
	inc	c
	jr	NZ, 00103$
	inc	b
	jr	NZ, 00103$
	inc	hl
00103$:
	ld	e, l
	ld	d, h
	ret
;src/test/resources/compiler/abi.c:14: u16 mixed(u8 a, u16 b, u8 c) __sdcccall(1) { return a + b + c; }
;	---------------------------------
; Function mixed
; ---------------------------------
_mixed::
	ld	l, a
	ld	h, #0x00
	add	hl, de
	ld	c, l
	ld	b, h
	ldhl	sp,	#2
	ld	a, (hl)
	ld	l, a
	ld	h, #0x00
	add	hl, bc
	ld	c, l
	ld	b, h
	pop	hl
	inc	sp
	jp	(hl)
;src/test/resources/compiler/abi.c:15: u8 pointer(const u8 *p) __sdcccall(1) { return *p; }
;	---------------------------------
; Function pointer
; ---------------------------------
_pointer::
	ld	a, (de)
	ret
;src/test/resources/compiler/abi.c:16: void caller(void) {
;	---------------------------------
; Function caller
; ---------------------------------
_caller::
;src/test/resources/compiler/abi.c:17: sink8=legacy8(1,2,3); sink16=legacy16(0x1234,0x5678,9); sink32=legacy32(0x12345678);
	ld	hl, #0x302
	push	hl
	ld	a, #0x01
	push	af
	inc	sp
	call	_legacy8
	add	sp, #3
	ld	hl, #_sink8
	ld	(hl), e
	ld	a, #0x09
	push	af
	inc	sp
	ld	de, #0x5678
	push	de
	ld	de, #0x1234
	push	de
	call	_legacy16
	add	sp, #5
	ld	hl, #_sink16
	ld	a, e
	ld	(hl+), a
	ld	(hl), d
	ld	de, #0x1234
	push	de
	ld	de, #0x5678
	push	de
	call	_legacy32
	add	sp, #4
	ld	c, l
	ld	b, h
	ld	hl, #_sink32
	ld	a, e
	ld	(hl+), a
	ld	a, d
	ld	(hl+), a
	ld	a, c
	ld	(hl+), a
	ld	(hl), b
;src/test/resources/compiler/abi.c:18: sink8=current8(1,2,3); sink16=current16(0x1234,0x5678,9); sink32=current32(0x12345678);
	ld	a, #0x03
	push	af
	inc	sp
	ld	e, #0x02
	ld	a, #0x01
	call	_current8
	ld	(#_sink8),a
	ld	a, #0x09
	push	af
	inc	sp
	ld	bc, #0x5678
	ld	de, #0x1234
	call	_current16
	ld	hl, #_sink16
	ld	a, c
	ld	(hl+), a
	ld	(hl), b
	ld	bc, #0x5678
	ld	de, #0x1234
	call	_current32
	ld	hl, #_sink32
	ld	a, c
	ld	(hl+), a
	ld	a, b
	ld	(hl+), a
	ld	a, e
	ld	(hl+), a
	ld	(hl), d
;src/test/resources/compiler/abi.c:19: sink16=mixed(1,0x2345,6); sink8=pointer((const u8*)0xc123);
	ld	a, #0x06
	push	af
	inc	sp
	ld	de, #0x2345
	ld	a, #0x01
	call	_mixed
	ld	hl, #_sink16
	ld	a, c
	ld	(hl+), a
	ld	(hl), b
	ld	de, #0xc123
	call	_pointer
	ld	(#_sink8),a
;src/test/resources/compiler/abi.c:20: }
	ret
;src/test/resources/compiler/abi.c:21: u16 mixed2(u16 a, u8 b, u16 c) __sdcccall(1) { return a + b + c; }
;	---------------------------------
; Function mixed2
; ---------------------------------
_mixed2::
	ld	l, a
	ld	h, #0x00
	add	hl, de
	ld	c, l
	ld	b, h
	ldhl	sp,	#2
	ld	a,	(hl+)
	ld	h, (hl)
	ld	l, a
	add	hl, bc
	ld	c, l
	ld	b, h
	pop	hl
	pop	af
	jp	(hl)
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
