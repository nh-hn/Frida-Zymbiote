cmake_minimum_required(VERSION 3.10)
project(yinject)
set(CMAKE_C_STANDARD 11)


# 定义主程序
add_executable(yinject kzx.c)


# 指定头文件目录
target_include_directories(yinject PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)