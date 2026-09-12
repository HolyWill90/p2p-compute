OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 60M
}

SECTIONS {
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : ALIGN(8) {
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
        *(.data .data.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(8) {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
    } > RAM
}
