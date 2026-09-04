SHELL := /bin/bash

BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(CURDIR)/out
# Gradle overrides this to src/jvmMain/resources/natives
RESOURCEDIR ?= $(CURDIR)/../../src/jvmMain/resources/natives

# Linux/Android nanotime is patched to CLOCK_BOOTTIME
GO_VERSION := 1.27.0
GO_DIR := $(BUILDDIR)/go-$(GO_VERSION)
GRADLE_USER_HOME ?= $(HOME)/.gradle
PATCHED_GO := GOTOOLCHAIN=local GOROOT="$(GO_DIR)" PATH="$(GO_DIR)/bin:$(PATH)"

export CGO_ENABLED := 1
export GOCACHE ?= $(BUILDDIR)/go-cache

HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m)

# Project JNI headers (vpn_jni.h)
JNI_INCLUDES := -I$(CURDIR)/jni/include

# JDK JNI headers. Gradle passes JAVA_HOME from the compile toolchain.
JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which java))))

ifeq ($(HOST_OS),darwin)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin
else ifeq ($(HOST_OS),linux)
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
else
  JDK_JNI_CFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/win32
endif

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

# Android NDK provides jni.h via --sysroot
GO_PLATFORM := $(shell uname -s | tr '[:upper:]' '[:lower:]')-$(NDK_GO_ARCH_MAP_$(shell uname -m))
GO_TARBALL := go$(GO_VERSION).$(GO_PLATFORM).tar.gz
GO_HASH_darwin-amd64 := d3314e25496e4381d71a5c51d2907e7af655d199f6780b549f015bd85fef4986
GO_HASH_darwin-arm64 := 90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e
GO_HASH_linux-amd64 := 675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685
GO_HASH_linux-arm64 := 51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda

android: $(DESTDIR)/libam-go.so

$(GRADLE_USER_HOME)/caches/golang/$(GO_TARBALL):
	mkdir -p "$(dir $@)"
	flock "$@.lock" -c ' \
	[ -f "$@" ] && exit 0; \
	curl -o "$@.tmp" "https://dl.google.com/go/$(GO_TARBALL)" && \
	echo "$(GO_HASH_$(GO_PLATFORM))  $@.tmp" | sha256sum -c && \
	mv "$@.tmp" "$@"'

$(GO_DIR)/.prepared: $(GRADLE_USER_HOME)/caches/golang/$(GO_TARBALL) \
		$(CURDIR)/goruntime-boottime-over-monotonic.diff
	mkdir -p "$(dir $@)"
	SHELL=/bin/bash flock "$@.lock" -c ' \
	[ -f "$@" ] && exit 0; \
	tar -C "$(dir $@)" --strip-components=1 -xzf "$<" && \
	patch -p1 -N -d "$(dir $@)" < "$(CURDIR)/goruntime-boottime-over-monotonic.diff" && \
	find "$(dir $@)pkg" -mindepth 1 -maxdepth 1 -type d -name "linux_*" -exec rm -rf {} +; \
	touch "$@"'

$(DESTDIR)/libam-go.so: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	@test -n "$(ANDROID_ARCH_NAME)" || (echo "ANDROID_ARCH_NAME required"; exit 1)
	@test -n "$(ANDROID_PACKAGE_NAME)" || (echo "ANDROID_PACKAGE_NAME required"; exit 1)
	@test -n "$(TARGET)" || (echo "TARGET required"; exit 1)
	@test -n "$(SYSROOT)" || (echo "SYSROOT required"; exit 1)
	$(eval CLANG_FLAGS := --target=$(TARGET) --sysroot=$(SYSROOT))
	$(PATCHED_GO) \
	CGO_CFLAGS="$(CLANG_FLAGS) $(subst -mthumb,-marm,$(CFLAGS)) $(JNI_INCLUDES)" \
	CGO_LDFLAGS="$(CLANG_FLAGS) $(LDFLAGS) -Wl,-soname=libam-go.so -llog -landroid" \
	CGO_ENABLED=1 \
	GOOS=android \
	GOARCH="$(NDK_GO_ARCH_MAP_$(ANDROID_ARCH_NAME))" \
	go build -tags 'android,notest,cgo' \
		-ldflags="-buildid=" \
		-trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .


$(DESTDIR)/libwg-linux-amd64.so: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	@test -f "$(JAVA_HOME)/include/jni.h" || (echo "jni.h not found; JAVA_HOME=$(JAVA_HOME)"; exit 1)
	@test -f "$(JAVA_HOME)/include/linux/jni_md.h" || (echo "linux/jni_md.h not found"; exit 1)
	$(PATCHED_GO) \
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=linux GOARCH=amd64 \
	go build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-windows-amd64.dll: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	$(PATCHED_GO) \
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=windows GOARCH=amd64 \
	CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
	go build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-windows-arm64.dll: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	$(PATCHED_GO) \
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=windows GOARCH=arm64 \
	CC=aarch64-w64-mingw32-gcc CXX=aarch64-w64-mingw32-g++ \
	go build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-darwin-amd64.dylib: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	$(PATCHED_GO) \
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=darwin GOARCH=amd64 \
	go build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

$(DESTDIR)/libwg-darwin-arm64.dylib: $(GO_DIR)/.prepared
	@mkdir -p "$(DESTDIR)"
	$(PATCHED_GO) \
	CGO_ENABLED=1 CGO_CFLAGS="$(DESKTOP_CGO_CFLAGS)" \
	GOOS=darwin GOARCH=arm64 \
	go build -tags 'notest,cgo' -ldflags="-buildid=" -trimpath -buildvcs=false \
		-o "$@" -buildmode=c-shared .

build_all: \
	$(foreach plat,$(PLATFORMS),$(DESTDIR)/libwg-$(plat).$(if $(findstring windows,$(plat)),dll,$(if $(findstring darwin,$(plat)),dylib,so)))


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