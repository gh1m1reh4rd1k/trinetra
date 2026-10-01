# ==============================================================================
# Shiv - Makefile (hardened + optimized)
#
#   make -j$(nproc) all        release build (O2 + LTO + full hardening)
#   make debug                 -Og -g3, hardening kept, no LTO
#   make san                   ASan + UBSan build (for finding memory bugs)
#   make tsan                  ThreadSanitizer build (for finding data races)
#   make pgo-gen / pgo-use     profile-guided optimization workflow
#                              (once a profile exists, plain make/install reuse it)
#   make checksec              verify the built binary really is hardened
#   make flags                 print the effective compiler/linker flags
#   sudo make install          build + install to /usr/bin
#
# Useful overrides:
#   ARCH=-march=x86-64-v3      portable AVX2 build (default: -march=native)
#   OLEVEL=-O3                 try -O3 instead of -O2 (benchmark it!)
#   LTO=0                      disable link-time optimization
#   FORTIFY=0                  disable _FORTIFY_SOURCE
#   ZEROINIT=1                 zero-init stack vars (extra hardening, some cost)
#   STRICT=1                   turn warnings into errors
#   STRIP=1                    strip symbols from the binary
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ------------------------------------------------------------------------------
# Help (what runs when the user types just 'make')
# ------------------------------------------------------------------------------
help:
	@echo "Available commands:"
	@echo "  make -j\$$(nproc) all  - Build the optimized + hardened binary"
	@echo "  sudo make install     - Install the binary"
	@echo "  sudo make uninstall   - Remove installed binary"
	@echo "  make clean            - Remove build files"
	@echo "  make check-installed  - Check installation status"
	@echo ""
	@echo "Build variants:"
	@echo "  make debug | san | tsan   - debug / ASan+UBSan / ThreadSanitizer builds"
	@echo "  make pgo-gen, pgo-use     - profile-guided optimization (see Makefile header)"
	@echo "  make checksec             - verify PIE/RELRO/NX/canary/fortify/CET on the binary"
	@echo "  make flags                - print the effective flags"

# ------------------------------------------------------------------------------
# Helpers: only use a flag if the installed compiler/linker really supports it
# ------------------------------------------------------------------------------
comma := ,
cc-option = $(shell echo 'int main(){}' | $(CXX) $(1) -x c++ -fsyntax-only - >/dev/null 2>&1 && echo $(1))
ld-option = $(shell echo 'int main(){}' | $(CXX) -x c++ - -o /dev/null $(1) >/dev/null 2>&1 && echo $(1))

# ------------------------------------------------------------------------------
# Tunables
# ------------------------------------------------------------------------------
CXX    ?= g++
BUILD  ?= release
ARCH   ?= -march=native
STRICT ?= 0
STRIP  ?= 0
ZEROINIT ?= 0
JOBS   ?= $(shell nproc 2>/dev/null || echo 2)
EXTRA_CXXFLAGS ?=
EXTRA_LDFLAGS  ?=

# ------------------------------------------------------------------------------
# Build variant selection
# ------------------------------------------------------------------------------
SAN_FLAGS :=

ifeq ($(BUILD),release)
  OLEVEL    ?= -O2
  LTO       ?= 1
  GC        ?= 1
  FORTIFY   ?= 1
  STATIC_RT ?= 1
else ifeq ($(BUILD),debug)
  OLEVEL    ?= -Og -g3 -fno-omit-frame-pointer
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 1
  STATIC_RT ?= 1
else ifeq ($(BUILD),san)
  OLEVEL    ?= -O1 -g3 -fno-omit-frame-pointer
  SAN_FLAGS := -fsanitize=address,undefined
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 0
  STATIC_RT ?= 0
else ifeq ($(BUILD),tsan)
  OLEVEL    ?= -O1 -g3 -fno-omit-frame-pointer
  SAN_FLAGS := -fsanitize=thread
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 0
  STATIC_RT ?= 0
else
  $(error Unknown BUILD '$(BUILD)' (use: release, debug, san, tsan))
endif

# ------------------------------------------------------------------------------
# Compiler
# ------------------------------------------------------------------------------
STD := -std=c++20 -pthread

# _FORTIFY_SOURCE=3 needs GCC >= 12; fall back to 2 on older compilers
GCC_MAJOR     := $(shell $(CXX) -dumpversion 2>/dev/null | cut -d. -f1)
FORTIFY_LEVEL := $(shell [ "$(GCC_MAJOR)" -ge 12 ] 2>/dev/null && echo 3 || echo 2)

# Performance flags
#  -fno-plt            : direct calls through GOT (pairs with -z now)
#  -fno-math-errno     : lets std::pow/sqrt inline (errno from math is never read)
#  -fvisibility=hidden : smaller binary, better inlining (it's an executable)
OPT_FLAGS := -pipe -fno-plt -fno-math-errno \
             -fvisibility=hidden -fvisibility-inlines-hidden

ifeq ($(GC),1)
  OPT_FLAGS += -ffunction-sections -fdata-sections
endif

# Correctness flags for raw-packet code:
#  -fno-strict-aliasing  : the code casts char* packet buffers to ip/tcphdr/ip6_hdr
#  -fno-strict-overflow  : signed overflow wraps instead of being optimized away
#  -fno-delete-null-pointer-checks : never let the optimizer drop a NULL check
SAFE_FLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

# Hardening (compile side)
HARDEN := -fPIE -fstack-protector-strong \
          $(call cc-option,-fstack-clash-protection) \
          $(call cc-option,-fcf-protection=full) \
          $(call cc-option,-fzero-call-used-regs=used-gpr) \
          -D_GLIBCXX_ASSERTIONS

ifeq ($(FORTIFY),1)
  HARDEN += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL)
endif
ifeq ($(ZEROINIT),1)
  HARDEN += $(call cc-option,-ftrivial-auto-var-init=zero)
endif

# Link-time optimization
LTO_FLAGS :=
ifeq ($(LTO),1)
  LTO_FLAGS := $(call cc-option,-flto=auto)
endif

# Profile-guided optimization (-fprofile-update=atomic: Shiv is multi-threaded)
# If a profile exists in pgo-data/, plain 'make' / 'make install' use it
# automatically. Run 'make pgo-clean' (or pass PGO=none) to opt out.
PGO_DIR   := $(CURDIR)/pgo-data
PGO_FLAGS :=
ifeq ($(origin PGO),undefined)
  ifneq ($(wildcard $(PGO_DIR)/*.gcda),)
    PGO := use
  endif
endif
ifeq ($(PGO),gen)
  PGO_FLAGS := -fprofile-generate -fprofile-update=atomic -fprofile-dir=$(PGO_DIR)
else ifeq ($(PGO),use)
  PGO_FLAGS := -fprofile-use -fprofile-dir=$(PGO_DIR) -fprofile-correction \
               $(call cc-option,-fprofile-partial-training) \
               -Wno-missing-profile -Wno-coverage-mismatch
endif

# Warnings
WARN := -Wall -Wextra -Wno-unused-parameter -Wformat -Wformat-security -Wvla
ifeq ($(STRICT),1)
  WARN += -Werror
endif

# Flags shared by compile AND link (LTO/PGO/sanitizers need them at link time)
CODEGEN := $(STD) $(OLEVEL) $(ARCH) $(OPT_FLAGS) $(SAFE_FLAGS) $(HARDEN) \
           $(LTO_FLAGS) $(PGO_FLAGS) $(SAN_FLAGS)

# ------------------------------------------------------------------------------
# Linker
# ------------------------------------------------------------------------------
LD_HARDEN := -pie -Wl,-z,relro,-z,now,-z,noexecstack \
             $(call ld-option,-Wl$(comma)-z$(comma)separate-code)

LD_OPT := -Wl,--as-needed,-O1,--hash-style=gnu
ifeq ($(GC),1)
  LD_OPT += -Wl,--gc-sections
endif
ifeq ($(STATIC_RT),1)
  LD_OPT += -static-libgcc -static-libstdc++
endif
ifeq ($(STRIP),1)
  LD_OPT += -Wl,--strip-all
endif

# Include and library paths
INCLUDES := -I/usr/include/liburing
LIB_DIRS := -L/usr/lib/x86_64-linux-gnu

# Libraries (linked AFTER the objects)
LIBS := -luring -lcurl -lssl -lcrypto -lz -lpcre2-8 -lpthread

CXXFLAGS := $(CODEGEN) $(WARN) -MMD -MP $(INCLUDES) $(EXTRA_CXXFLAGS)
LDFLAGS  := $(CODEGEN) $(LD_HARDEN) $(LD_OPT) $(LIB_DIRS) $(EXTRA_LDFLAGS)

# ------------------------------------------------------------------------------
# Sources / paths
# ------------------------------------------------------------------------------
SRCS := scan.cpp main.cpp utils.cpp public_db.cpp anomaly_analysis.cpp probe.cpp control.cpp async_io.cpp netns_split.cpp traceroute.cpp parser.cpp handler.cpp arp_handler.cpp debug.cpp dns_enum.cpp server.cpp ssl_enum.cpp simulations.cpp net_capture.cpp discover.cpp os_detect.cpp
OBJ_DIR := object
TARGET := shiv

# Absolute path of current source directory
CURRENT_DIR := $(CURDIR)
BINARY_PATH := /usr/bin/$(TARGET)
INSTALL_RECORD := /usr/local/share/$(TARGET).install_path

# No sudo needed (or required to exist) when already root
SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

# Object files in object directory
OBJS := $(addprefix $(OBJ_DIR)/, $(SRCS:.cpp=.o))

# ------------------------------------------------------------------------------
# Build rules
# ------------------------------------------------------------------------------
all: $(TARGET)

# Flags stamp: rewritten only when the compiler/flags change, so switching
# BUILD=..., ARCH=..., LTO=... etc. automatically rebuilds everything.
FLAGS_STAMP := $(OBJ_DIR)/.build_flags

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(FLAGS_STAMP): FORCE | $(OBJ_DIR)
	@printf '%s\n' '$(CXX) $(CXXFLAGS) :: $(LDFLAGS) $(LIBS)' | cmp -s - $@ 2>/dev/null || \
		printf '%s\n' '$(CXX) $(CXXFLAGS) :: $(LDFLAGS) $(LIBS)' > $@

FORCE:

# Link final binary
$(TARGET): $(OBJS) $(FLAGS_STAMP)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

# Compile source files to object directory (+ automatic header dependencies)
$(OBJ_DIR)/%.o: %.cpp $(FLAGS_STAMP) | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Header dependency files generated by -MMD -MP: editing scan.hpp, handler.hpp,
# etc. now correctly rebuilds every .cpp that includes them.
-include $(OBJS:.o=.d)

# ------------------------------------------------------------------------------
# Build variants (thin wrappers; switching variants rebuilds via the stamp)
# ------------------------------------------------------------------------------
debug:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=debug $(TARGET)

san:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=san $(TARGET)

tsan:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=tsan $(TARGET)

# ------------------------------------------------------------------------------
# PGO workflow:
#   1) make pgo-gen            builds an instrumented ./shiv
#   2) run ./shiv on a LAB target (SYN scan, large port range, a few retries,
#      IPv4+IPv6 if you use both). Let each scan finish normally (no Ctrl+C
#      kill -9) so the profile is written on exit.
#   3) make pgo-use            rebuilds with the collected profile
# ------------------------------------------------------------------------------
pgo-gen:
	@rm -rf $(PGO_DIR)
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=release PGO=gen $(TARGET)
	@echo "Instrumented build ready. Run ./$(TARGET) scans against a lab target,"
	@echo "let them finish, then run: make pgo-use"

pgo-use:
	@if ! ls $(PGO_DIR)/*.gcda >/dev/null 2>&1; then \
		echo "ERROR: no profile data in $(PGO_DIR). Run 'make pgo-gen' and exercise ./$(TARGET) first."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=release PGO=use $(TARGET)

pgo-clean:
	rm -rf $(PGO_DIR)

# ------------------------------------------------------------------------------
# Inspection
# ------------------------------------------------------------------------------
flags:
	@echo "BUILD    = $(BUILD)   (LTO=$(LTO) GC=$(GC) FORTIFY=$(FORTIFY) PGO=$(PGO))"
	@echo "CXXFLAGS = $(CXXFLAGS)"
	@echo "LDFLAGS  = $(LDFLAGS)"
	@echo "LIBS     = $(LIBS)"

# Verify the binary is actually hardened (this is what the old Makefile silently lacked)
checksec: $(TARGET)
	@echo "== hardening report for $(TARGET) =="
	@readelf -h $(TARGET) | grep -qE 'Type:[[:space:]]*DYN' \
		&& echo "  PIE (ASLR)        : yes" || echo "  PIE (ASLR)        : NO"
	@readelf -lW $(TARGET) | grep -q GNU_RELRO \
		&& echo "  RELRO             : yes" || echo "  RELRO             : NO"
	@readelf -dW $(TARGET) | grep -qE 'BIND_NOW|FLAGS.*NOW' \
		&& echo "  BIND_NOW (full)   : yes" || echo "  BIND_NOW (full)   : NO"
	@readelf -lW $(TARGET) | grep GNU_STACK | grep -q RWE \
		&& echo "  NX stack          : NO" || echo "  NX stack          : yes"
	@echo "  stack canary refs : $$(readelf -sW $(TARGET) | grep -c '__stack_chk_fail@')  (>0 = yes)"
	@echo "  fortified calls   : $$(readelf -sW $(TARGET) | grep -cE '__[a-z0-9_]+_chk@')  (>0 = yes)"
	@readelf -nW $(TARGET) | grep -qE 'IBT|SHSTK' \
		&& echo "  CET (IBT/SHSTK)   : yes" || echo "  CET (IBT/SHSTK)   : NO"

# ------------------------------------------------------------------------------
# Install / uninstall
# ------------------------------------------------------------------------------

# Quick check for installation conflicts (no compilation)
check-conflict:
	@echo "Checking for existing $(TARGET) installation..."
	@if [ -f $(BINARY_PATH) ]; then \
		SOURCE_DIR=$$(readlink -f $(BINARY_PATH) 2>/dev/null || echo ""); \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: $(TARGET) is already installed from: $$RECORDED_DIR"; \
			echo "This binary was built from: $(CURRENT_DIR)"; \
			echo ""; \
			echo "To prevent conflicts, you must:"; \
			echo "  1. Uninstall the existing version first: 'sudo make uninstall' in $$RECORDED_DIR"; \
			echo "  2. Or use a different binary name by changing TARGET in Makefile"; \
			exit 1; \
		elif [ -n "$$SOURCE_DIR" ] && [ "$$SOURCE_DIR" != "$(CURRENT_DIR)/$(TARGET)" ]; then \
			echo "ERROR: $(TARGET) is already installed from a different location"; \
			echo "Installed binary points to: $$SOURCE_DIR"; \
			echo "Current directory: $(CURRENT_DIR)"; \
			echo ""; \
			echo "Please uninstall the existing version first or use a different binary name"; \
			exit 1; \
		else \
			echo "✓ No conflict detected. Proceeding with installation..."; \
		fi; \
	else \
		echo "✓ No existing installation found. Proceeding..."; \
	fi

# Install binary with pre-check. The conflict check runs (and can abort) BEFORE
# any compilation, even under 'make -j'.
install:
	@$(MAKE) --no-print-directory check-conflict
	@$(MAKE) --no-print-directory -j$(JOBS) $(TARGET)
	@echo "Installing $(TARGET) to /usr/bin..."
	@$(SUDO) install -Dm755 $(TARGET) $(BINARY_PATH)
	@echo "$(CURRENT_DIR)" | $(SUDO) tee $(INSTALL_RECORD) > /dev/null 2>&1 || true
	@echo "✓ Done! You can now run '$(TARGET)' from anywhere"
	@echo "  Installation recorded from: $(CURRENT_DIR)"

# Force install (ignore conflicts, overwrite)
force-install:
	@$(MAKE) --no-print-directory -j$(JOBS) $(TARGET)
	@echo "WARNING: Force installing $(TARGET) - this will overwrite any existing installation"
	@sleep 1
	@$(SUDO) install -Dm755 $(TARGET) $(BINARY_PATH)
	@echo "$(CURRENT_DIR)" | $(SUDO) tee $(INSTALL_RECORD) > /dev/null 2>&1 || true
	@echo "✓ Force install complete from: $(CURRENT_DIR)"

# Remove binary with safety check
uninstall:
	@echo "Removing $(TARGET) from /usr/bin..."
	@if [ -f $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: This binary was installed from: $$RECORDED_DIR"; \
			echo "Current directory is: $(CURRENT_DIR)"; \
			echo "You are trying to uninstall from a different directory!"; \
			echo "Uninstall cancelled."; \
			exit 1; \
		else \
			$(SUDO) rm -f $(BINARY_PATH); \
			$(SUDO) rm -f $(INSTALL_RECORD); \
			echo "✓ Uninstalled!"; \
		fi; \
	else \
		echo "$(TARGET) is not installed in /usr/bin"; \
	fi

# Check installation status
check-installed:
	@if [ -f $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo "unknown"); \
		BIN_SOURCE=$$(readlink -f $(BINARY_PATH) 2>/dev/null || echo "unknown"); \
		echo "========================================="; \
		echo "$(TARGET) installation status:"; \
		echo "  Binary location: $(BINARY_PATH)"; \
		echo "  Binary source: $$BIN_SOURCE"; \
		echo "  Recorded directory: $$RECORDED_DIR"; \
		if [ "$$RECORDED_DIR" = "$(CURRENT_DIR)" ]; then \
			echo "  ✓ This is the current directory"; \
		else \
			echo "  ⚠ This is NOT the current directory"; \
		fi; \
		echo "========================================="; \
	else \
		echo "$(TARGET) is not installed"; \
	fi

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

# Clean build files
clean:
	rm -f $(TARGET)
	rm -rf $(OBJ_DIR)

# Clean everything including installed binary (use with caution!)
clean-all: clean pgo-clean
	@if [ -f $(BINARY_PATH) ]; then \
		echo "Removing installed binary as well..."; \
		$(SUDO) rm -f $(BINARY_PATH); \
		$(SUDO) rm -f $(INSTALL_RECORD); \
		echo "✓ Removed installed binary"; \
	fi

# ------------------------------------------------------------------------------
# Phony targets
# ------------------------------------------------------------------------------
.PHONY: all help FORCE debug san tsan pgo-gen pgo-use pgo-clean flags checksec \
        clean clean-all install force-install uninstall check-installed check-conflict
