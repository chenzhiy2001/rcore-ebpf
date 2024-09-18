
set -e

echo $(pwd)

pushd ./ebpf

builddir="/home/oslab/rCore-Tutorial-v3-eBPF/rcore-ebpf/user/build"
targetdir="/home/oslab/rCore-Tutorial-v3-eBPF/rcore-ebpf/user/target/riscv64gc-unknown-none-elf/release/"
ucoredir="/home/oslab/rCore-Tutorial-v3-eBPF/rcore-ebpf/ucore"

cur=$(pwd)

if ! command -v clang-12 &> /dev/null
then
    echo "clang-12 could not be found"
    exit -1
fi

pushd ./kern
make
popd 

pushd $ucoredir
make clean
make 
popd

userprogs=("naivetest" "maptest" "kernmaptest" "loadprogextest" "gdbserver")
kernprogs=("map" "time1" "context" "get_regs")
objcopy="riscv64-unknown-elf-objcopy"
for i in ${userprogs[@]};
do
    echo "cp ./user/${i}.o ${builddir}/elf/ebpf_user_${i}.elf"
    touch "${builddir}/app/ebpf_user_${i}.rs"
    # cp "./user/${i}.o" "${targetdir}/ebpf_user_${i}"
    # cp "./user/${i}.o" "${builddir}/elf/ebpf_user_${i}.elf"
    cp "${ucoredir}/build/riscv64/ebpf_user_${i}" "${targetdir}/ebpf_user_${i}"
done

for i in ${kernprogs[@]};
do
    echo "cp ./kern/${i}.o"
    touch "${builddir}/app/ebpf_kern_${i}.rs"
    cp "./kern/${i}.o" "${targetdir}/ebpf_kern_${i}"
    cp "./kern/${i}.o" "${builddir}/elf/ebpf_kern_${i}.elf"

done

popd 

exit 0