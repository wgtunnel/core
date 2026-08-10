cmake_minimum_required(VERSION 3.4.1)
project("WGTunnelBackend")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_link_options(LINKER:--build-id=none)
add_compile_options(-Wall -Werror)

# AmneziaWG tools (userspace wg / wg-quick)
set(AMNEZIA_TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../amneziawg-tools")

add_executable(libam-quick.so ${AMNEZIA_TOOLS_DIR}/src/wg-quick/android.c)
target_compile_options(libam-quick.so PUBLIC
	-std=gnu11
	-DAWG_PACKAGE_NAME=\"${ANDROID_PACKAGE_NAME}\"
)
target_link_libraries(libam-quick.so -ldl)

file(GLOB AM_SOURCES ${AMNEZIA_TOOLS_DIR}/src/*.c)
add_executable(libam.so ${AM_SOURCES})
target_include_directories(libam.so PUBLIC
	"${AMNEZIA_TOOLS_DIR}/src/uapi/linux/"
	"${AMNEZIA_TOOLS_DIR}/src/"
)
target_compile_options(libam.so PUBLIC
	-std=gnu11
	-DRUNSTATEDIR=\"/data/data/${ANDROID_PACKAGE_NAME}/cache\"
)

# Go userspace
set(GO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../backend")
set(JNI_DIR "${GO_DIR}/jni")

add_custom_target(libam-go.so
	WORKING_DIRECTORY "${GO_DIR}"
	COMMENT "Building amneziawg-go + JNI (android)"
	VERBATIM
	COMMAND "${ANDROID_HOST_PREBUILTS}/bin/make" android
		ANDROID_ARCH_NAME=${ANDROID_ARCH_NAME}
		ANDROID_PACKAGE_NAME=${ANDROID_PACKAGE_NAME}
		GRADLE_USER_HOME=${GRADLE_USER_HOME}
		CC=${CMAKE_C_COMPILER}
		CFLAGS=${CMAKE_C_FLAGS}
		LDFLAGS=${CMAKE_SHARED_LINKER_FLAGS}
		SYSROOT=${CMAKE_SYSROOT}
		TARGET=${CMAKE_C_COMPILER_TARGET}
		DESTDIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
		BUILDDIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../generated-src
	DEPENDS
      ${GO_DIR}/Makefile
      ${GO_DIR}/go.mod
      ${GO_DIR}/main_android.go
      ${GO_DIR}/jni/jni.go
      ${GO_DIR}/jni/include/vpn_jni.h
      ${GO_DIR}/jni/vpn_jni_shared.c
      ${GO_DIR}/jni/vpn_jni_android.c
	  ${GO_DIR}/jni/proxy_jni.c
)