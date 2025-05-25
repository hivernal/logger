OUTPUT := .output
CLANG ?= clang
SRC_DIR := ./logger
CUR_DIR := $(abspath .)
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OUTPUT := $(abspath ./libbpf)
LIBBPF_OBJ := $(abspath ./libbpf/usr/lib64/libbpf.a)

USER_SRC := $(wildcard $(SRC_DIR)/*.c)
BPF_HELPERS_SRC := $(SRC_DIR)/bpf/helpers.bpf.c
BPF_SRC := $(wildcard $(SRC_DIR)/bpf/*.bpf.c)
BPF_SRC := $(filter-out $(BPF_HELPERS_SRC),$(BPF_SRC))

USER_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OUTPUT)/%.o,$(USER_SRC))
BPF_SKELS := $(patsubst $(SRC_DIR)/bpf/%.bpf.c,$(SRC_DIR)/%.skel.h,$(BPF_SRC))
BPF_HELPERS_OBJS := $(patsubst $(SRC_DIR)/bpf/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_HELPERS_SRC))

BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath ./bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := $(SRC_DIR)/bpf/vmlinux.h
INCLUDES := -I$(LIBBPF_OUTPUT)/usr/include -I$(LIBBPF_SRC)/include/uapi -I$(CUR_DIR)
CFLAGS := -g -Wall -Wextra -Werror -Wconversion -Wsign-conversion
CLANG_CFLAGS := $(CFLAGS)
GCC_CFLAGS := $(CFLAGS) -Wduplicated-cond -Wduplicated-branches -Wlogical-op
APP=bpf

all: $(APP)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP) $(BPF_SKELS) $(VMLINUX)

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
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

$(VMLINUX): $(BPFTOOL)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: $(SRC_DIR)/bpf/%.bpf.c $(SRC_DIR)/bpf/%.h $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CLANG_CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $@

$(SRC_DIR)/%.skel.h: $(OUTPUT)/%.bpf.o $(BPF_HELPERS_OBJS) | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/$*.skel.o $(filter %.o,$^)
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/$*.skel.o > $@

$(OUTPUT)/%.o: $(BPF_SKELS) $(SRC_DIR)/%.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(GCC_CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP): $(USER_OBJS) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(GCC_CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
