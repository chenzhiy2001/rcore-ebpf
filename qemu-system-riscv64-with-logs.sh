tty > ./qemu_tty
qemu-system-riscv64 "$@" | tee ./code_debug_qemu_output_history.txt
