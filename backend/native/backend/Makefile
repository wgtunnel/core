# SPDX-License-Identifier: Apache-2.0
# Desktop (default) + Android (NDK/CMake: make android ...)

GO ?= go
BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(CURDIR)/out
# Gradle overrides this to src/jvmMain/resources/natives
RESOURCEDIR ?= $(CURDIR)/../../src/jvmMain/resources/natives

export CGO_ENABLED := 1
export GOCACHE ?= $(BUILDDIR)/go-cache

# Project JNI headers (vpn_jni.h)
JNI_INCLUDES := -I$(CURDIR)/jni/include

# JDK JNI headers (required on desktop; NDK supplies these on Android)
JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which java))))
ifeq ($(HOST_OS),darwin)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin
else ifeq ($(HOST_OS),linux)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
else
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/win32
endif

# Desktop cgo flags: JDK + our headers
DESKTOP_CGO_CFLAGS := $(JDK_JNI_CFLAGS) $(JNI_INCLUDES)

HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m)

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which java))))

ifeq ($(HOST_OS),darwin)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin
else ifeq ($(HOST_OS),linux)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
else
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/win32
endif

JNI_INCLUDES := -I$(CURDIR)/jni/include
DESKTOP_CGO_CFLAGS := $(JDK_JNI_CFLAGS) $(JNI_INCLUDES)

NDK_GO_ARCH_MAP_x86 := 386
NDK_GO_ARCH_MAP_x86_64 := amd64
NDK_GO_ARCH_MAP_amd64 := amd64
NDK_GO_ARCH_MAP_arm := arm
NDK_GO_ARCH_MAP_arm64 := arm64
NDK_GO_ARCH_MAP_aarch64 := arm64

ifeq ($(HOST_OS),darwin)
PLATFORMS := darwin-amd64 darwin-arm64 linux-amd64 windows-amd64 windows-arm64
else
PLATFORMS := linux-amd64 windows-amd64
endif

.PHONY: default desktop android build_all copy_to_resources clean

default: desktop
desktop: copy_to_resources

# ---------------------------------------------------------------------------
# Android (unchanged idea — NDK provides jni.h via --sysroot)
# ---------------------------------------------------------------------------
android: $(DESTDIR)/libam-go.so

$(DESTDIR)/libam-go.so:
	@mkdir -p "$(DESTDIR)"
	@test -n "$(ANDROID_ARCH_NAME)" || (echo "ANDROID_ARCH_NAME required"; exit 1)
	@test -n "$(ANDROID_PACKAGE_NAME)" || (echo "ANDROID_PACKAGE_NAME required"; exit 1)
	@test -n "$(TARGET)" || (echo "TARGET required"; exit 1)
	@test -n "$(SYSROOT)" || (echo "SYSROOT required"; exit 1)
	$(eval CLANG_FLAGS := --target=$(TARGET) --sysroot=$(SYSROOT))
	CGO_CFLAGS="$(CLANG_FLAGS) $(subst -mthumb,-marm,$(CFLAGS)) $(JNI_INCLUDES)" \
	CGO_LDFLAGS="$(CLANG_FLAGS) $(LDFLAGS) -Wl,-soname=libam-go.so -llog -landroid" \
	CGO_ENABLED=1 \
	GOOS=android \
	GOARCH="$(NDK_GO_ARCH_MAP_$(ANDROID_ARCH_NAME))" \
	$(GO) build -tags 'android,notest,cgo' \
		-ldflags="-X github.com/amnezia-vpn/amneziawg-go/ipc.socketDirectory=/data/data/$(ANDROID_PACKAGE_NAME)/cache/amneziawg -buildid=" \
		-trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

# ---------------------------------------------------------------------------
# Desktop — note DESKTOP_CGO_CFLAGS (JDK + jni/include)
# ---------------------------------------------------------------------------
$(DESTDIR)/libwg-linux-amd64.so:
	@mkdir -p "$(DESTDIR)"
	@test -f "$(JAVA_HOME)/include/jni.h" || (echo "jni.h not found; JAVA_HOME=$(JAVA_HOME)"; exit 1)
	@test -f "$(JAVA_HOME)/include/linux/jni_md.h" || (echo "linux/jni_md.h not found"; exit 1)
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=linux GOARCH=amd64 \
	$(GO) build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-windows-amd64.dll:
	@mkdir -p "$(DESTDIR)"
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=windows GOARCH=amd64 \
	CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
	$(GO) build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-windows-arm64.dll:
	@mkdir -p "$(DESTDIR)"
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=windows GOARCH=arm64 \
	CC=aarch64-w64-mingw32-gcc CXX=aarch64-w64-mingw32-g++ \
	$(GO) build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-darwin-amd64.dylib:
	@mkdir -p "$(DESTDIR)"
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=darwin GOARCH=amd64 \
	$(GO) build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-darwin-arm64.dylib:
	@mkdir -p "$(DESTDIR)"
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=darwin GOARCH=arm64 \
	$(GO) build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

build_all: \
	$(foreach plat,$(PLATFORMS),$(DESTDIR)/libwg-$(plat).$(if $(findstring windows,$(plat)),dll,$(if $(findstring darwin,$(plat)),dylib,so)))

# JNI-oriented resource layout (not JNA names — use what your NativeLoader expects)
copy_to_resources: build_all
	@for plat in $(PLATFORMS); do \
		os=`echo "$$plat" | cut -d- -f1`; \
		arch=`echo "$$plat" | cut -d- -f2`; \
		subdir=; \
		if [ "$$os" = "linux" ] && [ "$$arch" = "amd64" ]; then subdir=linux-x86_64; fi; \
		if [ "$$os" = "windows" ] && [ "$$arch" = "amd64" ]; then subdir=windows-x86_64; fi; \
		if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then subdir=windows-aarch64; fi; \
		if [ "$$os" = "darwin" ] && [ "$$arch" = "amd64" ]; then subdir=darwin-x86_64; fi; \
		if [ "$$os" = "darwin" ] && [ "$$arch" = "arm64" ]; then subdir=darwin-aarch64; fi; \
		libext=so; \
		if [ "$$os" = "windows" ]; then libext=dll; fi; \
		if [ "$$os" = "darwin" ]; then libext=dylib; fi; \
		dest_dir="$(RESOURCEDIR)/$$subdir"; \
		mkdir -p "$$dest_dir"; \
		cp "$(DESTDIR)/libwg-$$plat.$$libext" "$$dest_dir/libwg.$$libext"; \
		echo "Copied $$plat -> $$dest_dir/libwg.$$libext"; \
	done

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)"

.DELETE_ON_ERROR: