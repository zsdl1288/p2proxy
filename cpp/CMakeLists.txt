cmake_minimum_required(VERSION 3.25)
project(p2proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Dependencies are linked statically (triplet x64-windows-static-md); only the
# VC++ runtime is a DLL, because msquic does not support a static CRT. The
# release bundles those DLLs next to the exe.

set(P2PX_VERSION "dev" CACHE STRING "Version shown in the app")
# Self-update: the GitHub "owner/name" that publishes releases, and the
# base64 Ed25519 key that signs them. Without both, updates are disabled.
set(P2PX_REPO "" CACHE STRING "GitHub repository for updates")
set(P2PX_UPDATE_PUBKEY "" CACHE STRING "Release signing public key (base64)")

find_package(msquic CONFIG REQUIRED) # target: msquic
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-webview2 CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)

add_executable(p2proxy WIN32
  src/main.cpp
  src/app.cpp
  src/util.cpp
  src/crypto.cpp
  src/netutil.cpp
  src/stun.cpp
  src/signal.cpp
  src/quic.cpp
  src/tunnel.cpp
  src/server.cpp
  src/client.cpp
  src/socks.cpp
  src/web.cpp
  src/cert.cpp
  src/update.cpp
  src/app.rc
)

target_compile_definitions(p2proxy PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
  QUIC_API_ENABLE_PREVIEW_FEATURES # BBR congestion control is a preview API in msquic 2.4
  P2PX_VERSION="${P2PX_VERSION}"
  P2PX_REPO="${P2PX_REPO}"
  P2PX_UPDATE_PUBKEY="${P2PX_UPDATE_PUBKEY}"
)
target_compile_options(p2proxy PRIVATE /W3 /utf-8 /EHsc)
# app.rc embeds these; without this, editing them would not rebuild the exe.
set_source_files_properties(src/app.rc PROPERTIES OBJECT_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/ui.html;${CMAKE_CURRENT_SOURCE_DIR}/src/app.ico")

# Release signing tool, used by the release workflow (see tools/sign.cpp).
add_executable(p2proxy-sign tools/sign.cpp)
target_compile_options(p2proxy-sign PRIVATE /W3 /utf-8)
target_link_libraries(p2proxy-sign PRIVATE unofficial-sodium::sodium)

# vcpkg's msquic is always a DLL. Ship it next to the exe: Windows looks there
# first, so a different msquic.dll in System32 (Windows 11 has one) is never used.
add_custom_command(TARGET p2proxy POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:msquic> $<TARGET_FILE_DIR:p2proxy>)

target_link_libraries(p2proxy PRIVATE
  msquic
  httplib::httplib
  nlohmann_json::nlohmann_json
  unofficial::webview2::webview2
  unofficial-sodium::sodium
  ws2_32 iphlpapi winhttp bcrypt crypt32 ncrypt shell32 ole32 user32 advapi32 shlwapi
)
