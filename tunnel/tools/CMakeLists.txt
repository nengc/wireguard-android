# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.

cmake_minimum_required(VERSION 3.4.1)
project("WireGuard")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_link_options(LINKER:--build-id=none)
add_compile_options(-Wall -Werror)

# 设置预编译库目录
set(PREBUILT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt)
set(PREBUILT_LIBS_DIR ${PREBUILT_DIR}/libs)
set(PREBUILT_INCLUDE_DIR ${PREBUILT_DIR}/include)

# 添加 u2t_tlcp 头文件路径
include_directories(${PREBUILT_INCLUDE_DIR})

# 检查并添加预编译的 libu2t_tlcp_android.so
if(EXISTS ${PREBUILT_LIBS_DIR}/${ANDROID_ABI}/libu2t_tlcp_android.so)
    message(STATUS "Found prebuilt libu2t_tlcp_android.so for ${ANDROID_ABI}")
    
    # 导入预编译库
    add_library(u2t_tlcp_android SHARED IMPORTED)
    
    set_target_properties(u2t_tlcp_android PROPERTIES
        IMPORTED_LOCATION ${PREBUILT_LIBS_DIR}/${ANDROID_ABI}/libu2t_tlcp_android.so
        IMPORTED_NO_SONAME TRUE
    )
    
    # 可选：为库添加编译定义（如果需要）
    # target_compile_definitions(u2t_tlcp_android INTERFACE U2T_TLCP_ENABLED=1)
    
    # 创建自定义命令来复制库到输出目录
    add_custom_command(
        OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libu2t_tlcp_android.so
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PREBUILT_LIBS_DIR}/${ANDROID_ABI}/libu2t_tlcp_android.so
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libu2t_tlcp_android.so
        DEPENDS ${PREBUILT_LIBS_DIR}/${ANDROID_ABI}/libu2t_tlcp_android.so
        COMMENT "Copying libu2t_tlcp_android.so for ${ANDROID_ABI}"
    )
    
    add_custom_target(copy_u2t_tlcp_android ALL
        DEPENDS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libu2t_tlcp_android.so
    )
    
else()
    message(WARNING "Prebuilt libu2t_tlcp_android.so not found for ${ANDROID_ABI} at ${PREBUILT_LIBS_DIR}/${ANDROID_ABI}/libu2t_tlcp_android.so")
endif()


# 添加 U2T TLCP JNI 代码
add_library(u2t_tlcp_jni SHARED
    u2t_tlcp_jni.cpp
)

target_include_directories(u2t_tlcp_jni PRIVATE
    ${PREBUILT_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(u2t_tlcp_jni PRIVATE
    -std=c++11
    -Wall
    -Werror
)

# 链接 u2t_tlcp_android 库
if(TARGET u2t_tlcp_android)
    target_link_libraries(u2t_tlcp_jni u2t_tlcp_android)
endif()

# 如果需要，也链接其他库
target_link_libraries(u2t_tlcp_jni
    -llog
    -landroid
)



add_executable(libwg-quick.so wireguard-tools/src/wg-quick/android.c ndk-compat/compat.c)
target_compile_options(libwg-quick.so PUBLIC -std=gnu11 -include ${CMAKE_CURRENT_SOURCE_DIR}/ndk-compat/compat.h -DWG_PACKAGE_NAME=\"${ANDROID_PACKAGE_NAME}\")
target_link_libraries(libwg-quick.so -ldl)

file(GLOB WG_SOURCES wireguard-tools/src/*.c ndk-compat/compat.c)
add_executable(libwg.so ${WG_SOURCES})
target_include_directories(libwg.so PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/wireguard-tools/src/uapi/linux/" "${CMAKE_CURRENT_SOURCE_DIR}/wireguard-tools/src/")
target_compile_options(libwg.so PUBLIC -std=gnu11 -include ${CMAKE_CURRENT_SOURCE_DIR}/ndk-compat/compat.h -DRUNSTATEDIR=\"/data/data/${ANDROID_PACKAGE_NAME}/cache\")

add_custom_target(libwg-go.so WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libwg-go" COMMENT "Building wireguard-go" VERBATIM COMMAND "${ANDROID_HOST_PREBUILTS}/bin/make"
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
)

# Strip unwanted ELF sections to prevent DT_FLAGS_1 warnings on old Android versions
file(GLOB ELF_CLEANER_SOURCES elf-cleaner/*.c elf-cleaner/*.cpp)
add_custom_target(elf-cleaner COMMENT "Building elf-cleaner" VERBATIM COMMAND cc
        -O2 -DPACKAGE_NAME="elf-cleaner" -DPACKAGE_VERSION="" -DCOPYRIGHT=""
        -o "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner" ${ELF_CLEANER_SOURCES}
)
add_custom_command(TARGET libwg.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"
        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg.so>")
add_dependencies(libwg.so elf-cleaner)
add_custom_command(TARGET libwg-quick.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"
        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg-quick.so>")
add_dependencies(libwg-quick.so elf-cleaner)
