OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
    TEXT (rx)  : ORIGIN = 0x80000000, LENGTH = 64K
    TOHOST (rw): ORIGIN = 0x80010000, LENGTH = 4K
    RAM (rw)   : ORIGIN = 0x80011000, LENGTH = 15M
}

SECTIONS {
    .text : {
        *(.text.init)
        *(.text .text.*)
    } > TEXT

    .tohost (NOLOAD) : {
        *(.tohost)
    } > TOHOST

    .rodata : ALIGN(8) { *(.rodata .rodata.*) *(.srodata .srodata.*) } > RAM
    .data : ALIGN(8) {
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
        *(.data .data.*)
    } > RAM
    .bss (NOLOAD) : ALIGN(8) { *(.sbss .sbss.*) *(.bss .bss.*) } > RAM
    _stack_end = ORIGIN(RAM) + LENGTH(RAM);
}
