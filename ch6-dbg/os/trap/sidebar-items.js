window.SIDEBAR_ITEMS = {"fn":[["enable_timer_interrupt","enable timer interrupt in sie CSR"],["init","initialize CSR `stvec` as the entry of `__alltraps`"],["set_kernel_trap_entry",""],["set_user_trap_entry",""],["trap_from_kernel","Unimplement: traps/interrupts/exceptions from kernel mode Todo: Chapter 9: I/O device"],["trap_handler","handle an interrupt, exception, or system call from user space"],["trap_return","set the new addr of __restore asm function in TRAMPOLINE page, set the reg a0 = trap_cx_ptr, reg a1 = phy addr of usr page table, finally, jump to new addr of __restore asm function"]],"mod":[["context","Implementation of [`TrapContext`]"]],"struct":[["TrapContext","trap context structure containing sstatus, sepc and registers"]]};