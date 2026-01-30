#!/bin/bash

# 支持的架构和libc变体
ARCHES="arm mips mipsel x86"
LIBCS="glibc musl uclibc"

# 工具链根目录
TOOLCHAIN_ROOT="/"

# 遍历所有架构和libc组合
echo "检查可用的工具链和编译器："
echo "================================="

for arch in $ARCHES; do
    for libc in $LIBCS; do
        # 构建工具链目录路径
        if [ "$libc" = "uclibc" ]; then
            toolchain_dir="${TOOLCHAIN_ROOT}${arch}-${libc}-tool-chain"
        else
            toolchain_dir="${TOOLCHAIN_ROOT}${arch}-${libc}-toolchain"
        fi
        
        # 检查工具链目录是否存在
        if [ -d "$toolchain_dir" ]; then
            # 检查output/host/bin目录是否存在
            bin_dir="${toolchain_dir}/output/host/bin"
            if [ -d "$bin_dir" ]; then
                echo -e "\n工具链：${arch}-${libc}"
                echo "目录：$toolchain_dir"
                echo "bin目录：$bin_dir"
                echo "可用的gcc编译器："
                # 查找gcc编译器
                gcc_list=$(ls "$bin_dir"/*gcc* 2>/dev/null || echo "无可用gcc")
                echo "$gcc_list"
            else
                echo -e "\n工具链：${arch}-${libc}"
                echo "目录：$toolchain_dir"
                echo "状态：output/host/bin目录不存在"
            fi
        else
            echo -e "\n工具链：${arch}-${libc}"
            echo "状态：工具链目录不存在"
        fi
    done
done

echo "================================="
echo "检查完成！"
