#!/bin/bash

# 定义颜色输出
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

# 检查目录是否存在
OUTPUT_DIR="/libnvram/output"
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${RED}Error: $OUTPUT_DIR directory does not exist!${NC}"
    exit 1
fi

echo -e "${YELLOW}Checking libnvram.so architecture in each directory...${NC}"
echo ""

# 遍历所有子目录
for dir in "$OUTPUT_DIR"/*; do
    if [ -d "$dir" ]; then
        # 提取目录名（去除路径）
        dir_name=$(basename "$dir")
        
        # 提取架构信息（目录名的第一部分，如 arm、mipsel、x86 等）
        arch_from_dir=$(echo "$dir_name" | cut -d'-' -f1)
        
        # 检查 libnvram.so 文件是否存在
        lib_file="$dir/libnvram.so"
        if [ ! -f "$lib_file" ]; then
            echo -e "${RED}Error: $lib_file does not exist!${NC}"
            continue
        fi
        
        # 使用 file 命令获取文件架构信息
        file_output=$(file "$lib_file")
        
        # 检查架构是否匹配
        arch_match=false
        case "$arch_from_dir" in
            "arm")
                if echo "$file_output" | grep -q "ARM"; then
                    arch_match=true
                fi
                ;;
            "mipsel")
                if echo "$file_output" | grep -q "MIPS" && echo "$file_output" | grep -q "LSB"; then
                    arch_match=true
                fi
                ;;
            "mips")
                if echo "$file_output" | grep -q "MIPS" && echo "$file_output" | grep -q "MSB"; then
                    arch_match=true
                fi
                ;;
            "x86")
                if echo "$file_output" | grep -q "Intel 80386" || echo "$file_output" | grep -q "x86-64"; then
                    arch_match=true
                fi
                ;;
        esac
        
        # 输出检查结果
        if [ "$arch_match" = true ]; then
            echo -e "${GREEN}✓ $dir_name: Architecture matches${NC}"
        else
            echo -e "${RED}✗ $dir_name: Architecture mismatch! Got: $file_output${NC}"
        fi
    fi
done

echo ""
echo -e "${YELLOW}Architecture check completed!${NC}"