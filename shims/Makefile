# Build the plzn interop shims and libplzn-shim.a.
#
#   make            -- build helper library + unit tests, and any shim whose
#                      library/toolchain is detected (Botan, OpenSSL, LibreSSL,
#                      GnuTLS, wolfSSL, BoringSSL, Go, rustls). A shim is only
#                      relinked when its source, the helper archive, or the library
#                      it links against is newer than the binary, so this is
#                      cheap to run every time (check.sh does).
#   make configure  -- persist checkout roots in build/config.mk
#   make libplzn-shim -- build only the C++ helper library (no TLS deps)
#   make check      -- build and run the helper library and Go unit tests
#   make botan      -- build the Botan shim (needs libbotan-3 + headers)
#   make openssl    -- build the OpenSSL shim (needs OpenSSL 3.x)
#   make libressl   -- build the LibreSSL shim (PLZN_LIBRESSL_ROOT or pkg-config)
#   make gnutls     -- build the GnuTLS shim
#   make wolfssl    -- build the wolfSSL shim
#   make boringssl  -- build the BoringSSL shim (PLZN_BORINGSSL_ROOT)
#   make go         -- build the Go standard-library crypto/tls shim
#   make rustls     -- build the rustls shim crate
#   make clean
#
# Library locations can be overridden:
#   BOTAN_CFLAGS / BOTAN_LIBS      OpenSSL: OPENSSL_CFLAGS / OPENSSL_LIBS
#   GNUTLS_CFLAGS / GNUTLS_LIBS    wolfSSL: WOLFSSL_CFLAGS / WOLFSSL_LIBS
#   PLZN_BORINGSSL_ROOT           Required for BoringSSL: checkout with build/*.a
#   LibreSSL: LIBRESSL_CFLAGS / LIBRESSL_LIBS, or PLZN_LIBRESSL_ROOT (an
#   install prefix with include/ and lib/); else pkg-config under
#   /usr/lib/libressl/pkgconfig (Arch) or /usr/local/lib/pkgconfig.
# Other libraries default to pkg-config detection.
#
# The library file each shim links against (BOTAN_LIB_FILE, OPENSSL_LIB_FILES)
# is a prerequisite of the shim binary, so rebuilding or upgrading the library
# relinks the shim on the next `make` instead of leaving a binary that dies on
# its first call into a changed ABI.

CXX      ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic
AR       ?= ar
GO       ?= go
CARGO    ?= cargo
BUILD    := build
CONFIG_MK := $(BUILD)/config.mk

# `make configure` writes this optional include. Command-line assignments still
# override it, so switching a checkout is one command and subsequent plain
# `make` / `check.sh` runs keep using the selected library.
-include $(CONFIG_MK)

COMMON_SRC := common/json.cpp common/shim_config.cpp common/shim_socket.cpp common/shim_error.cpp common/app_data_protocol.cpp
COMMON_OBJ := $(patsubst common/%.cpp,$(BUILD)/common_%.o,$(COMMON_SRC))
COMMON_LIB := $(BUILD)/libplzn-shim.a
COMMON_HDR := common/plzn_shim.h
COMMON_INC := -Icommon

BOTAN_SHIM   := $(BUILD)/botan_shim
OPENSSL_SHIM := $(BUILD)/openssl_shim
LIBRESSL_SHIM := $(BUILD)/libressl_shim
LIBRESSL_EXPECTATIONS := $(BUILD)/libressl-expectations.json
GNUTLS_SHIM  := $(BUILD)/gnutls_shim
WOLFSSL_SHIM := $(BUILD)/wolfssl_shim
BORINGSSL_SHIM := $(BUILD)/boringssl_shim
GO_SHIM      := $(BUILD)/go_tls_shim
GO_SRC       := $(wildcard go/*.go) go/go.mod
RUSTLS_SHIM  := $(BUILD)/rustls_shim

# --- Botan detection ---
# Prefer an in-tree Botan dev checkout (the library under test) when
# PLZN_BOTAN_ROOT points at one; otherwise fall back to pkg-config's
# system install. The dev checkout exposes newer TLS callbacks (e.g. the
# DTLS monotonic-clock hook) the shim relies on.
#
# Persist checkout selection with `make configure PLZN_BOTAN_ROOT=/path`.
PLZN_BOTAN_ROOT ?=
ifneq ($(PLZN_BOTAN_ROOT),)
  BOTAN_CFLAGS   ?= -I$(PLZN_BOTAN_ROOT)/build/include/public
  BOTAN_LIBS     ?= -L$(PLZN_BOTAN_ROOT) -lbotan-3 -Wl,-rpath,$(PLZN_BOTAN_ROOT)
  BOTAN_LIB_FILE ?= $(PLZN_BOTAN_ROOT)/libbotan-3.so
else
  BOTAN_CFLAGS   ?= $(shell pkg-config --cflags botan-3 2>/dev/null)
  BOTAN_LIBS     ?= $(shell pkg-config --libs botan-3 2>/dev/null)
  BOTAN_LIBDIR   := $(shell pkg-config --variable=libdir botan-3 2>/dev/null)
  BOTAN_LIB_FILE ?= $(if $(BOTAN_LIBDIR),$(wildcard $(BOTAN_LIBDIR)/libbotan-3.so),)
endif

# --- OpenSSL detection ---
OPENSSL_CFLAGS    ?= $(shell pkg-config --cflags libssl libcrypto 2>/dev/null)
OPENSSL_LIBS      ?= $(shell pkg-config --libs libssl libcrypto 2>/dev/null)
OPENSSL_LIBDIR    := $(shell pkg-config --variable=libdir libssl 2>/dev/null)
OPENSSL_LIB_FILES ?= $(if $(OPENSSL_LIBDIR),$(wildcard $(OPENSSL_LIBDIR)/libssl.so $(OPENSSL_LIBDIR)/libcrypto.so),)

# --- LibreSSL detection ---
# LibreSSL installs alongside OpenSSL under the same libssl/libcrypto names, so
# it is never found through the default pkg-config path; distributions put it
# in a separate prefix (Arch: /usr/lib/libressl). A PLZN_LIBRESSL_ROOT install
# prefix wins; otherwise look in the known side-by-side pkg-config dirs and
# accept the result only if its opensslv.h really is LibreSSL. The shim gets an
# rpath so it never resolves the system OpenSSL's same-named libraries.
PLZN_LIBRESSL_ROOT ?=
ifneq ($(PLZN_LIBRESSL_ROOT),)
  LIBRESSL_CFLAGS    ?= -I$(PLZN_LIBRESSL_ROOT)/include
  LIBRESSL_LIBDIR    := $(PLZN_LIBRESSL_ROOT)/lib
else
  LIBRESSL_PKG_PATH  := /usr/lib/libressl/pkgconfig:/usr/local/lib/libressl/pkgconfig:/opt/libressl/lib/pkgconfig
  LIBRESSL_PKG_INC   := $(shell PKG_CONFIG_LIBDIR=$(LIBRESSL_PKG_PATH) pkg-config --variable=includedir libssl 2>/dev/null)
  ifneq ($(and $(LIBRESSL_PKG_INC),$(shell grep -l LIBRESSL_VERSION_NUMBER $(LIBRESSL_PKG_INC)/openssl/opensslv.h 2>/dev/null)),)
    LIBRESSL_CFLAGS  ?= $(shell PKG_CONFIG_LIBDIR=$(LIBRESSL_PKG_PATH) pkg-config --cflags libssl libcrypto 2>/dev/null)
    LIBRESSL_LIBDIR  := $(shell PKG_CONFIG_LIBDIR=$(LIBRESSL_PKG_PATH) pkg-config --variable=libdir libssl 2>/dev/null)
  endif
endif
ifneq ($(LIBRESSL_LIBDIR),)
  LIBRESSL_LIBS      ?= -L$(LIBRESSL_LIBDIR) -lssl -lcrypto -Wl,-rpath,$(LIBRESSL_LIBDIR)
  LIBRESSL_LIB_FILES ?= $(wildcard $(LIBRESSL_LIBDIR)/libssl.so $(LIBRESSL_LIBDIR)/libcrypto.so)
endif

# --- GnuTLS detection ---
GNUTLS_CFLAGS   ?= $(shell pkg-config --cflags gnutls 2>/dev/null)
GNUTLS_LIBS     ?= $(shell pkg-config --libs gnutls 2>/dev/null)
GNUTLS_LIBDIR   := $(shell pkg-config --variable=libdir gnutls 2>/dev/null)
GNUTLS_LIB_FILE ?= $(if $(GNUTLS_LIBDIR),$(wildcard $(GNUTLS_LIBDIR)/libgnutls.so),)

# --- wolfSSL detection ---
WOLFSSL_CFLAGS   ?= $(shell pkg-config --cflags wolfssl 2>/dev/null)
WOLFSSL_LIBS     ?= $(shell pkg-config --libs wolfssl 2>/dev/null)
WOLFSSL_LIBDIR   := $(shell pkg-config --variable=libdir wolfssl 2>/dev/null)
WOLFSSL_LIB_FILE ?= $(if $(WOLFSSL_LIBDIR),$(wildcard $(WOLFSSL_LIBDIR)/libwolfssl.so),)

# --- BoringSSL detection ---
# BoringSSL deliberately does not install pkg-config metadata. Point this at a
# CMake-built checkout explicitly; there is no default checkout path. Its
# upstream PacketedBio is compiled into the shim so the
# oracle uses BoringSSL's packeted-BIO design, adapted to acknowledge plzn's
# deterministic timer assertion/update controls.
PLZN_BORINGSSL_ROOT ?=
BORINGSSL_CFLAGS    ?= -I$(PLZN_BORINGSSL_ROOT)/include -I$(PLZN_BORINGSSL_ROOT)/ssl/test
BORINGSSL_LIB_FILES := $(PLZN_BORINGSSL_ROOT)/build/libssl.a $(PLZN_BORINGSSL_ROOT)/build/libcrypto.a
BORINGSSL_LIBS      ?= $(BORINGSSL_LIB_FILES) -lpthread
BORINGSSL_PACKETED_BIO := boringssl/packeted_bio.cpp boringssl/packeted_bio.h
BORINGSSL_EXPECTATIONS := $(BUILD)/boringssl-expectations.json
GO_EXPECTATIONS        := $(BUILD)/go-expectations.json

.PHONY: all configure libplzn-shim check clean botan openssl libressl gnutls wolfssl boringssl boringssl-config go go-test rustls detect

all: $(COMMON_LIB) $(BUILD)/test_common detect

# Finish the archive before recursive shim builds, including under make -j.
detect: $(COMMON_LIB)
	@echo "== plzn shims build =="
	@if [ -n "$(BOTAN_LIBS)" ]; then $(MAKE) --no-print-directory botan; \
	 else echo "botan: libbotan-3 not found via pkg-config; skipping (set BOTAN_LIBS to build)"; fi
	@if [ -n "$(OPENSSL_LIBS)" ]; then $(MAKE) --no-print-directory openssl; \
	 else echo "openssl: libssl not found via pkg-config; skipping (set OPENSSL_LIBS to build)"; fi
	@if [ -n "$(LIBRESSL_LIBS)" ]; then $(MAKE) --no-print-directory libressl; \
	 else echo "libressl: not found; skipping (set PLZN_LIBRESSL_ROOT or LIBRESSL_LIBS to build)"; fi
	@if [ -n "$(GNUTLS_LIBS)" ]; then $(MAKE) --no-print-directory gnutls; \
	 else echo "gnutls: libgnutls not found via pkg-config; skipping (set GNUTLS_LIBS to build)"; fi
	@if [ -n "$(WOLFSSL_LIBS)" ]; then $(MAKE) --no-print-directory wolfssl; \
	 else echo "wolfssl: libwolfssl not found via pkg-config; skipping (set WOLFSSL_LIBS to build)"; fi
	@if [ -n "$(strip $(PLZN_BORINGSSL_ROOT))" ]; then \
	   $(MAKE) --no-print-directory boringssl; \
	 else echo "boringssl: not configured; skipping (set PLZN_BORINGSSL_ROOT)"; fi
	@if command -v "$(GO)" >/dev/null 2>&1; then $(MAKE) --no-print-directory go; \
	 else echo "go: toolchain not found; skipping"; fi
	@$(MAKE) --no-print-directory rustls

$(BUILD):
	@mkdir -p $(BUILD)

configure: | $(BUILD)
	@tmp="$(CONFIG_MK).tmp"; \
	  { echo "# Generated by make configure; command-line values override these."; \
	    printf '%s\n' 'PLZN_BOTAN_ROOT := $(PLZN_BOTAN_ROOT)'; \
	    printf '%s\n' 'PLZN_BORINGSSL_ROOT := $(PLZN_BORINGSSL_ROOT)'; \
	    printf '%s\n' 'PLZN_LIBRESSL_ROOT := $(PLZN_LIBRESSL_ROOT)'; \
	  } > "$$tmp"; \
	  mv "$$tmp" "$(CONFIG_MK)"
	@echo "wrote $(CONFIG_MK)"

$(BUILD)/common_%.o: common/%.cpp $(COMMON_HDR) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(COMMON_INC) -c $< -o $@

libplzn-shim: $(COMMON_LIB)

$(COMMON_LIB): $(COMMON_OBJ) Makefile | $(BUILD)
	$(RM) $@
	$(AR) rcs $@ $(COMMON_OBJ)

$(BUILD)/test_common: common/test_common.cpp $(COMMON_LIB) $(COMMON_HDR) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(COMMON_INC) common/test_common.cpp $(COMMON_LIB) -o $@

check: $(BUILD)/test_common go-test
	@echo "== libplzn-shim unit tests =="
	@$(BUILD)/test_common

# `botan` / `openssl` are aliases; the file rules carry the real prerequisites
# so an up-to-date shim is not relinked. The alias reports which library the
# binary links, since that is the question when a shim starts crashing.
botan: $(BOTAN_SHIM)
	@echo "$(BOTAN_SHIM): links $(or $(BOTAN_LIB_FILE),$(BOTAN_LIBS))"

openssl: $(OPENSSL_SHIM)
	@echo "$(OPENSSL_SHIM): links $(or $(OPENSSL_LIB_FILES),$(OPENSSL_LIBS))"

libressl: $(LIBRESSL_SHIM) $(LIBRESSL_EXPECTATIONS)
	@echo "$(LIBRESSL_SHIM): links $(or $(LIBRESSL_LIB_FILES),$(LIBRESSL_LIBS))"

gnutls: $(GNUTLS_SHIM)
	@echo "$(GNUTLS_SHIM): links $(or $(GNUTLS_LIB_FILE),$(GNUTLS_LIBS))"

wolfssl: $(WOLFSSL_SHIM)
	@echo "$(WOLFSSL_SHIM): links $(or $(WOLFSSL_LIB_FILE),$(WOLFSSL_LIBS))"

boringssl: boringssl-config $(BORINGSSL_SHIM) $(BORINGSSL_EXPECTATIONS)
	@echo "$(BORINGSSL_SHIM): links $(PLZN_BORINGSSL_ROOT)"

boringssl-config:
	@if [ -z "$(strip $(PLZN_BORINGSSL_ROOT))" ]; then \
	  echo "error: BoringSSL requires PLZN_BORINGSSL_ROOT=/path/to/built/boringssl" >&2; exit 1; \
	 fi
	@for file in include/openssl/ssl.h build/libssl.a build/libcrypto.a; do \
	  if [ ! -f "$(PLZN_BORINGSSL_ROOT)/$$file" ]; then \
	    echo "error: PLZN_BORINGSSL_ROOT is missing $$file: $(PLZN_BORINGSSL_ROOT)" >&2; exit 1; \
	  fi; \
	 done

go: $(GO_SHIM) $(GO_EXPECTATIONS)
	@echo "$(GO_SHIM): $$($(GO) version)"

# Keep rustls out of plzn's Cargo dependency graph. Its standalone crate still
# depends on plzn for the shared JSON config and application-data protocol. It
# is not a default workspace member, so ordinary plzn builds do not select it.
# Cargo can still reuse the root workspace's existing build artifacts.
rustls: | $(BUILD)
	$(CARGO) build --locked --manifest-path rustls/Cargo.toml
	cp ../target/debug/rustls_shim $(RUSTLS_SHIM)
	@echo "built $(RUSTLS_SHIM)"

go-test:
	@if command -v "$(GO)" >/dev/null 2>&1; then \
	  cd go && CGO_ENABLED=0 $(GO) test ./...; \
	 else \
	  echo "go: toolchain not found; skipping tests"; \
	 fi

$(BOTAN_SHIM): botan/botan_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(BOTAN_LIB_FILE) | $(BUILD)
	@if [ -z "$(BOTAN_LIBS)" ]; then echo "error: BOTAN_LIBS not set and pkg-config found nothing"; exit 1; fi
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(BOTAN_CFLAGS) \
	    botan/botan_shim.cpp $(COMMON_LIB) $(BOTAN_LIBS) -o $@
	@echo "built $@"

$(OPENSSL_SHIM): openssl/openssl_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(OPENSSL_LIB_FILES) | $(BUILD)
	@if [ -z "$(OPENSSL_LIBS)" ]; then echo "error: OPENSSL_LIBS not set and pkg-config found nothing"; exit 1; fi
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(OPENSSL_CFLAGS) \
	    openssl/openssl_shim.cpp $(COMMON_LIB) $(OPENSSL_LIBS) -o $@
	@echo "built $@"

$(LIBRESSL_SHIM): libressl/libressl_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(LIBRESSL_LIB_FILES) | $(BUILD)
	@if [ -z "$(LIBRESSL_LIBS)" ]; then echo "error: LibreSSL not found; set PLZN_LIBRESSL_ROOT or LIBRESSL_LIBS"; exit 1; fi
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(LIBRESSL_CFLAGS) \
	    libressl/libressl_shim.cpp $(COMMON_LIB) $(LIBRESSL_LIBS) -o $@
	@echo "built $@"

$(GNUTLS_SHIM): gnutls/gnutls_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(GNUTLS_LIB_FILE) | $(BUILD)
	@if [ -z "$(GNUTLS_LIBS)" ]; then echo "error: GNUTLS_LIBS not set and pkg-config found nothing"; exit 1; fi
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(GNUTLS_CFLAGS) \
	    gnutls/gnutls_shim.cpp $(COMMON_LIB) $(GNUTLS_LIBS) -o $@
	@echo "built $@"

$(WOLFSSL_SHIM): wolfssl/wolfssl_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(WOLFSSL_LIB_FILE) | $(BUILD)
	@if [ -z "$(WOLFSSL_LIBS)" ]; then echo "error: WOLFSSL_LIBS not set and pkg-config found nothing"; exit 1; fi
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(WOLFSSL_CFLAGS) \
	    wolfssl/wolfssl_shim.cpp $(COMMON_LIB) $(WOLFSSL_LIBS) -o $@
	@echo "built $@"

ifneq ($(strip $(PLZN_BORINGSSL_ROOT)),)
$(BORINGSSL_SHIM): boringssl/boringssl_shim.cpp $(COMMON_LIB) $(COMMON_HDR) $(BORINGSSL_LIB_FILES) $(BORINGSSL_PACKETED_BIO) | $(BUILD) boringssl-config
	$(CXX) $(CXXFLAGS) $(COMMON_INC) $(BORINGSSL_CFLAGS) \
	    boringssl/boringssl_shim.cpp boringssl/packeted_bio.cpp $(COMMON_LIB) $(BORINGSSL_LIBS) -o $@
	@echo "built $@"
else
# Even a previously built shim must not make an explicit BoringSSL target
# succeed without the caller choosing which checkout to use.
$(BORINGSSL_SHIM): boringssl-config
endif

$(BORINGSSL_EXPECTATIONS): boringssl/boringssl-expectations.json | $(BUILD)
	cp $< $@

$(GO_EXPECTATIONS): go/go-expectations.json | $(BUILD)
	cp $< $@

$(LIBRESSL_EXPECTATIONS): libressl/libressl-expectations.json | $(BUILD)
	cp $< $@

$(GO_SHIM): $(GO_SRC) | $(BUILD)
	cd go && CGO_ENABLED=0 $(GO) build -trimpath -o "$(abspath $@)" .
	@echo "built $@"

clean:
	rm -rf $(BUILD)
