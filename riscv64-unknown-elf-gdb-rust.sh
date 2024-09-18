# initially we use this script to enable rust-gdb because rust-gdb gives better representation of rust string structures
# which hels us filter out the string address using regex and get string content.
# now we have hookpoints which grabs string content using GDB/MI API so rust-gdb is no longer needed.
export RUST_GDB=riscv64-unknown-elf-gdb
rust-gdb "$@"