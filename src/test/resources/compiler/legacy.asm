;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.1.6 #12539 (Mac OS X x86_64)
;--------------------------------------------------------
	.module legacy
	.optsdcc -mgbz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _legacyMixed
	.globl _legacyPointer
	.globl _legacy32
	.globl _legacy16
	.globl _legacy8
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
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
;src/test/resources/compiler/legacy.c:5: u8 legacy8(u8 a,u8 b,u8 c) { return a+b+c; }
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
;src/test/resources/compiler/legacy.c:6: u16 legacy16(u16 a,u16 b,u8 c) { return a+b+c; }
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
;	spillPairReg hl
;	spillPairReg hl
	ld	h, #0x00
;	spillPairReg hl
;	spillPairReg hl
	add	hl, bc
	ld	e, l
	ld	d, h
	ret
;src/test/resources/compiler/legacy.c:7: u32 legacy32(u32 a) { return a+1; }
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
;	spillPairReg hl
;	spillPairReg hl
	ld	l, a
;	spillPairReg hl
;	spillPairReg hl
	add	sp, #4
	ret
;src/test/resources/compiler/legacy.c:8: u8 legacyPointer(const u8 *p) { return *p; }
;	---------------------------------
; Function legacyPointer
; ---------------------------------
_legacyPointer::
	ldhl	sp,	#2
	ld	a, (hl+)
	ld	c, a
	ld	b, (hl)
	ld	a, (bc)
	ld	e, a
	ret
;src/test/resources/compiler/legacy.c:9: u16 legacyMixed(u8 a,u16 b,u8 c) { return a+b+c; }
;	---------------------------------
; Function legacyMixed
; ---------------------------------
_legacyMixed::
	ldhl	sp,	#2
	ld	a, (hl+)
	ld	c, a
	ld	b, #0x00
	ld	a,	(hl+)
	ld	h, (hl)
	ld	l, a
	add	hl, bc
	ld	c, l
	ld	b, h
	ldhl	sp,	#5
	ld	l, (hl)
;	spillPairReg hl
;	spillPairReg hl
	ld	h, #0x00
;	spillPairReg hl
;	spillPairReg hl
	add	hl, bc
	ld	e, l
	ld	d, h
	ret
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
