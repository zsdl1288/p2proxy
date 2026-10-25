@echo off
rem Builds p2proxy.exe into build\. Extra arguments go to CMake, e.g.
rem   build.cmd -DP2PX_VERSION=v2.0.0
rem Needs Visual Studio (or Build Tools) with C++, and vcpkg in P2PX_VCPKG
rem (defaults to ..\.tools\vcpkg).
setlocal
set "ROOT=%~dp0"
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (echo Visual Studio C++ tools not found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
rem vcvars points VCPKG_ROOT at Visual Studio's own vcpkg; use ours.
if not defined P2PX_VCPKG set "P2PX_VCPKG=%ROOT%..\.tools\vcpkg"
set "VCPKG_ROOT=%P2PX_VCPKG%"
set "PATH=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
cmake -S "%ROOT%." -B "%ROOT%build" -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  "-DCMAKE_TOOLCHAIN_FILE=%P2PX_VCPKG%\scripts\buildsystems\vcpkg.cmake" ^
  -DVCPKG_TARGET_TRIPLET=x64-windows-static-md ^
  "-DVCPKG_INSTALLED_DIR=%ROOT%build\vcpkg_installed" %* || exit /b 1
cmake --build "%ROOT%build" || exit /b 1
