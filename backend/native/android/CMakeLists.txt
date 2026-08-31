cmake_minimum_required(VERSION 3.22.1)
project("WGTunnelBackend")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_link_options(LINKER:--build-id=none)
add_compile_options(-Wall -Werror)


set(JNI_LIBS_DIR
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../backend-android-jni/src/main/jniLibs/${ANDROID_ABI}")

# AmneziaWG tools (userspace wg / wg-quick)
set(AMNEZIA_TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../amneziawg-tools")

add_executable(libam-quick.so ${AMNEZIA_TOOLS_DIR}/src/wg-quick/android.c)
target_compile_options(libam-quick.so PUBLIC
		-std=gnu11
		-DAWG_PACKAGE_NAME=\"${ANDROID_PACKAGE_NAME}\"
)
target_link_libraries(libam-quick.so -ldl)
add_custom_command(TARGET libam-quick.so POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory "${JNI_LIBS_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy
		"$<TARGET_FILE:libam-quick.so>"
		"${JNI_LIBS_DIR}/libam-quick.so"
		COMMENT "Install libam-quick.so → jniLibs/${ANDROID_ABI}"
)

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
add_custom_command(TARGET libam.so POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory "${JNI_LIBS_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy
		"$<TARGET_FILE:libam.so>"
		"${JNI_LIBS_DIR}/libam.so"
		COMMENT "Install libam.so to jniLibs/${ANDROID_ABI}"
)

# Go userspace and JNI and libam-go.so
set(GO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../backend")
set(AMGO_OUT "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libam-go.so")

add_custom_command(
		OUTPUT "${AMGO_OUT}"
		COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
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
		COMMAND ${CMAKE_COMMAND} -E make_directory "${JNI_LIBS_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${AMGO_OUT}" "${JNI_LIBS_DIR}/libam-go.so"
		WORKING_DIRECTORY "${GO_DIR}"
		COMMENT "Building + installing libam-go.so for ${ANDROID_ABI}"
		VERBATIM
		DEPENDS
		${GO_DIR}/Makefile
		${GO_DIR}/goruntime-boottime-over-monotonic.diff
		${GO_DIR}/go.mod
		${GO_DIR}/main_android.go
		${GO_DIR}/jni/jni.go
		${GO_DIR}/jni/include/vpn_jni.h
		${GO_DIR}/jni/vpn_jni_shared.c
		${GO_DIR}/jni/vpn_jni_android.c
		${GO_DIR}/jni/proxy_jni.c
		${GO_DIR}/jni/bootstrap_jni.c
		${GO_DIR}/bootstrap/bypass/handle_android.go
		${GO_DIR}/bootstrap/bypass/iface.go
		${GO_DIR}/bootstrap/bypass/tunnel.go
		${GO_DIR}/bootstrap/bypass/tunnel_android.go
		${GO_DIR}/tunwrap/wrap.go
		${GO_DIR}/vpn/vpn_shared.go
)

add_custom_target(libam-go.so ALL DEPENDS "${AMGO_OUT}")