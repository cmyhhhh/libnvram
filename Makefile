# 支持的架构和libc变体
ARCHES = arm mips mipsel x86
LIBCS = glibc musl uclibc

# 工具链根目录
TOOLCHAIN_DIR = /

# 源文件和目标文件定义
SOURCES = nvram.c
TARGET = libnvram.so

# 编译选项
CFLAGS = -O2 -fPIC -Wall -fno-stack-protector
LDFLAGS = -shared -nostdlib

# 动态编译器和输出目录规则
define BUILD_RULE
$(1)-$(2):
	@mkdir -p output/$(1)-$(2)
	$$(MAKE) -B output/$(1)-$(2)/$(TARGET) ARCH=$(1) LIBC=$(2)

output/$(1)-$(2)/$(TARGET): $$(SOURCES)
	@mkdir -p $$(dir $$@)
	# 根据架构和libc选择正确的工具链和编译器
	$$(eval TRIPLET_ARM_GLIBC := arm-buildroot-linux-gnueabi)
	$$(eval TRIPLET_ARM_MUSL := arm-buildroot-linux-musleabi)
	$$(eval TRIPLET_ARM_UCLIBC := arm-buildroot-linux-uclibcgnueabi)
	$$(eval TRIPLET_MIPS_GLIBC := mips-buildroot-linux-gnu)
	$$(eval TRIPLET_MIPS_MUSL := mips-buildroot-linux-musl)
	$$(eval TRIPLET_MIPS_UCLIBC := mips-buildroot-linux-uclibc)
	$$(eval TRIPLET_MIPSEL_GLIBC := mipsel-buildroot-linux-gnu)
	$$(eval TRIPLET_MIPSEL_MUSL := mipsel-buildroot-linux-musl)
	$$(eval TRIPLET_MIPSEL_UCLIBC := mipsel-buildroot-linux-uclibc)
	$$(eval TRIPLET_X86_GLIBC := i586-buildroot-linux-gnu)
	$$(eval TRIPLET_X86_MUSL := i586-buildroot-linux-musl)
	$$(eval TRIPLET_X86_UCLIBC := i586-buildroot-linux-uclibc)
	# 选择对应的编译器三元组
	$$(eval COMPILER_TRIPLET := $$(TRIPLET_$$(shell echo $(1) | tr a-z A-Z)_$$(shell echo $(2) | tr a-z A-Z)))
	$$(eval TOOLCHAIN_NAME := $(1)-$(2)-toolchain)
	$$(eval COMPILER := /$$(TOOLCHAIN_NAME)/output/host/bin/$$(COMPILER_TRIPLET)-gcc)
	$$(COMPILER) $(CFLAGS) $(LDFLAGS) $$^ -o $$@
endef

# 生成所有架构和libc的构建规则
$(foreach arch,$(ARCHES),$(foreach libc,$(LIBCS),$(eval $(call BUILD_RULE,$(arch),$(libc))))) 

# 主构建目标：编译所有架构和libc变体
all: $(foreach arch,$(ARCHES),$(foreach libc,$(LIBCS),$(arch)-$(libc)))

# 清理目标
clean:
	rm -rf output

.PHONY: all clean $(foreach arch,$(ARCHES),$(foreach libc,$(LIBCS),$(arch)-$(libc)))
