OUTPUT := .output
CLANG ?= clang
SRC_DIR := ./logger
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OUTPUT := $(abspath ./libbpf)
LIBBPF_OBJ := $(abspath ./libbpf/usr/lib64/libbpf.a)

ALL_SRC := $(wildcard $(SRC_DIR)/*.c)
USER_SRC := $(filter-out %.bpf.c,$(ALL_SRC))
BPF_SRC := $(filter %.bpf.c,$(ALL_SRC))
USER_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OUTPUT)/%.o,$(USER_SRC))
BPF_OBJS := $(patsubst $(SRC_DIR)/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SRC))
BPF_SKELS := $(patsubst %.bpf.c,%.skel.h,$(BPF_SRC))
SKELETON := $(SRC_DIR)/logger.skel.h

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
VMLINUX := $(SRC_DIR)/vmlinux.h
INCLUDES := -I$(LIBBPF_OUTPUT)/usr/include -I$(LIBBPF_SRC)/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
APP=bpf

all: $(APP)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP) $(SKELETON) $(VMLINUX)

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

$(OUTPUT)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $@

$(SRC_DIR)/%.skel.h: $(BPF_OBJS) | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/$*.bpf.o $(filter %.o,$^) 
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/$*.bpf.o > $@

$(OUTPUT)/%.o: $(SKELETON) $(SRC_DIR)/%.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP): $(USER_OBJS) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
