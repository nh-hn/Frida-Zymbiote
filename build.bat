@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: Android SDK 根目录
set "SDK_ROOT=E:\andriodsdk"

:: Android NDK 路径
set "NDK_ROOT=%SDK_ROOT%\ndk\25.1.8937393"

:: CMake 和 Ninja 可执行文件路径
set "CMAKE_EXE=%SDK_ROOT%\cmake\3.22.1\bin\cmake.exe"
set "NINJA_EXE=%SDK_ROOT%\cmake\3.22.1\bin\ninja.exe"

:: Android NDK CMake 工具链路径
set "TOOLCHAIN=%NDK_ROOT%\build\cmake\android.toolchain.cmake"

:: 清理旧构建目录
rmdir /s /q build 2>nul
mkdir build
cd build

:: 生成构建文件
"%CMAKE_EXE%" -G Ninja ^
  -DCMAKE_TOOLCHAIN_FILE=%TOOLCHAIN% ^
  -DANDROID_ABI=arm64-v8a ^
  -DANDROID_PLATFORM=android-21 ^
  -DCMAKE_MAKE_PROGRAM=%NINJA_EXE% ^
  ..

:: 编译项目
"%CMAKE_EXE%" --build .

cd ..

:: 复制可执行文件到项目根目录
copy build\yInject yInject


:: 清理 build 目录
rmdir /s /q build

echo Build done. Executable "demo" is at %CD%
pause
