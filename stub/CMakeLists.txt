# 设置 CMake 最低版本要求为 3.10，并定义工程名为 Stub，语言为 C
cmake_minimum_required(VERSION 3.10)
project(Stub C)

# 检查是否为 Android 平台，如果不是则报错
if(NOT ANDROID)
    message(FATAL_ERROR "This project is designed for Android NDK.")
endif()

# 获取 C 编译器所在目录（通常是 NDK 的工具链目录）
get_filename_component(NDK_BIN_DIR ${CMAKE_C_COMPILER} DIRECTORY)

# 在 NDK_BIN_DIR 中查找 llvm-objcopy 工具，不使用默认路径
find_program(OBJCOPY NAMES llvm-objcopy PATHS ${NDK_BIN_DIR} NO_DEFAULT_PATH)


# 定义编译器额外选项
set(EXTRA_FLAGS
        -Oz                          # 优化为最小体积
        -fPIC                        # 生成位置无关代码
        -fno-stack-protector          # 禁用栈保护
        -ffreestanding               # 不依赖标准库
        -fno-exceptions              # 禁用异常
        -fno-asynchronous-unwind-tables  # 禁用异常展开表
)

# 定义存放特定 ABI 的编译标志
set(STUB_FLAGS "")

# 针对 ARM64 ABI 启用 BTI（Branch Target Identification）分支保护
if(ANDROID_ABI STREQUAL "arm64-v8a")
    list(APPEND STUB_FLAGS "-mbranch-protection=bti")
endif()


# 定义链接脚本路径
set(HELPER_LDS "${CMAKE_CURRENT_SOURCE_DIR}/helper.lds")

# 定义链接器额外参数
set(EXTRA_LINK_ARGS
        "-nostdlib"                  # 不使用标准库
        "-Wl,-static"                # 静态链接
        "-Wl,--gc-sections"          # 丢弃未使用的段
        "-Wl,-T,${HELPER_LDS}"       # 使用自定义链接脚本
)

# 定义模块库（共享库，但不加前缀 lib）
add_library(stub MODULE stub.c
        stub.h)

# 给 stub 目标添加编译选项
target_compile_options(stub PRIVATE ${EXTRA_FLAGS} ${STUB_FLAGS})

# 给 stub 目标添加链接选项
target_link_options(stub PRIVATE ${EXTRA_LINK_ARGS})

# 设置目标属性
set_target_properties(stub PROPERTIES
        PREFIX ""                     # 去掉默认的 lib 前缀
        LINK_DEPENDS "${HELPER_LDS}"  # 指定链接依赖文件
)

# 定义 objcopy 转换选项
set(OBJCOPY_FLAGS "-O" "binary" "-j" ".payload")

# 使用 objcopy 从编译好的模块提取 payload 部分生成二进制文件
add_custom_command(
        OUTPUT stub_bin
        COMMAND ${OBJCOPY} ${OBJCOPY_FLAGS} $<TARGET_FILE:stub> stub.bin
        DEPENDS stub
        COMMENT "Extracting STUB.bin using objcopy"
)

# 使用 Python 脚本将二进制文件转换为 C 头文件
add_custom_command(
        OUTPUT stub_header
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/bin2header.py
        STUB.bin ../../stub.h stub_binary
        DEPENDS stub
        COMMENT "Converting STUB.bin to header using Python"
)

# 创建一个自定义构建目标，确保 stub_bin 和 stub_header 在构建时生成
add_custom_target(build_stub ALL DEPENDS stub_bin stub_header)