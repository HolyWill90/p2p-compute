    .section .text.init
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, _stack_end
    # The test's RVTEST_CODE_BEGIN expands inline from here
    # (test_macros.h defines _start, so we tail-jump to avoid a frame).
    # Actually: _start IS defined by the test itself via
    # RVTEST_CODE_BEGIN, so our entry is not needed. The linker
    # resolves ENTRY(_start) to the test's own _start.
