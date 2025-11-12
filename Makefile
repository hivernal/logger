# From linux/version.h.
LINUX_KERNEL_VERSION := $$(( ($$(uname -r | cut -d. -f1) << 16) + \
			     ($$(uname -r | cut -d. -f2) << 8) ))
NPROC := $$( nproc )
OUTPUT := .output
CLANG ?= clang
SRC_DIR := ./logger
CUR_DIR := $(abspath .)
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OUTPUT := $(abspath ./libbpf)
LIBBPF_OBJ := $(abspath ./libbpf/usr/lib64/libbpf.a)

USER_SRC := $(wildcard $(SRC_DIR)/*.c)
# BPF_HELPERS_SRC := $(SRC_DIR)/bpf/helpers.bpf.c
BPF_SRC := $(wildcard $(SRC_DIR)/bpf/*.bpf.c)
# BPF_SRC := $(filter-out $(BPF_HELPERS_SRC),$(BPF_SRC))

USER_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OUTPUT)/%.o,$(USER_SRC))
BPF_SKELS := $(patsubst $(SRC_DIR)/bpf/%.bpf.c,$(SRC_DIR)/%.skel.h,$(BPF_SRC))
# BPF_HELPERS_OBJS := $(patsubst $(SRC_DIR)/bpf/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_HELPERS_SRC))

BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath ./bpftool/src)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := $(SRC_DIR)/bpf/vmlinux.h
FEATURE_PROBE := $(SRC_DIR)/bpf/feature_probe.h
INCLUDES := -I$(LIBBPF_OUTPUT)/usr/include -I$(LIBBPF_SRC)/include/uapi -I$(CUR_DIR)
CFLAGS := -g -Wall -Wextra -Werror -Wconversion -Wsign-conversion
CLANG_CFLAGS := $(CFLAGS)
GCC_CFLAGS := $(CFLAGS) -Wduplicated-cond -Wduplicated-branches -Wlogical-op
APP=system_logger

all: $(APP)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP) $(BPF_SKELS) $(VMLINUX) $(FEATURE_PROBE)

$(OUTPUT) $(LIBBPF_OUTPUT) $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUTPUT)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		DESTDIR=$(LIBBPF_OUTPUT)	      			      \
		install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC)

$(VMLINUX): $(BPFTOOL)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(FEATURE_PROBE): $(BPFTOOL)
	sudo $(BPFTOOL) feature probe full macro > $@
	$(Q)echo "#define LINUX_KERNEL_VERSION $(LINUX_KERNEL_VERSION)" >> $@
	$(Q)echo "#define GET_LINUX_KERNEL_VERSION(a,b) (((a) << 16) + ((b) << 8))" >> $@
	$(Q)echo "#define NPROC $(NPROC)" >> $@



$(OUTPUT)/%.bpf.o: $(SRC_DIR)/bpf/%.bpf.c $(SRC_DIR)/bpf/%.h $(LIBBPF_OBJ) $(VMLINUX) $(FEATURE_PROBE) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CLANG_CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $@

$(SRC_DIR)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	# $(Q)$(BPFTOOL) gen object $(OUTPUT)/$*.skel.o $(filter %.o,$^)
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/$*.bpf.o > $@

$(OUTPUT)/%.o: $(BPF_SKELS) $(SRC_DIR)/%.c | $(OUTPUT)
	$(call msg,CLANG,$@)
	$(Q)$(CLANG) $(CLANG_CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP): $(USER_OBJS) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(CLANG_CFLAGS) $^ $(ALL_LDFLAGS) -lcrypto -lelf -lz -o $@
