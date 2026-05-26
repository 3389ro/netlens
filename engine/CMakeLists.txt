cmake_minimum_required(VERSION 3.20)

# -----------------------------------------------------------------------------
# NetLens engine — C++20 static library exposing a C ABI (netlens_engine.h).
# Consumed by the Win32 UI in this tree (linked statically into NetLens.exe).
# Any other C-ABI consumer can link the same .lib + include the same header.
# All public entry points are in src/ffi.cpp; the rest of src/ is the scan
# engine forked from the upstream NetLens source.
# -----------------------------------------------------------------------------

project(netlens_engine
    DESCRIPTION "NetLens scan engine — C ABI static library"
    LANGUAGES CXX)

# Version is supplied by the parent build (build.ps1 reads the top-level
# VERSION file and passes -DNETLENS_VERSION=…). When building standalone
# via plain CMake without that scaffold, fall back to "0.0.0" so the
# build still succeeds.
if(NOT DEFINED NETLENS_VERSION)
    set(NETLENS_VERSION "0.0.0")
endif()
add_compile_definitions(NETLENS_VERSION_STR="${NETLENS_VERSION}")
message(STATUS "netlens_engine version: ${NETLENS_VERSION}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ship a single self-contained .lib — static CRT so the eventual .exe has no
# runtime DLL dependency on msvcp/vcruntime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    add_compile_definitions(
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS)
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG /Oy /GL")
endif()

set(ENGINE_SOURCES
    src/ffi.cpp
    src/core/NetworkAdapterService.cpp
    src/core/IpAddressUtils.cpp
    src/core/IpRangeParser.cpp
    src/core/ScanPresetService.cpp
    src/core/NetworkScanner.cpp
    src/core/PingService.cpp
    src/core/PortScanner.cpp
    src/core/DnsResolver.cpp
    src/core/MacResolver.cpp
    src/core/VendorResolver.cpp
    src/core/OuiData.cpp
    src/core/ServiceDetector.cpp
    src/core/ServiceFingerprinter.cpp
    src/core/SnmpClient.cpp
    src/core/PrinterSnmpScanner.cpp
    src/core/UdpDiscoveryService.cpp
    src/core/VersionAdvisory.cpp
    src/core/VersionAnnotator.cpp
    src/core/VendorShortener.cpp
    src/core/EnrichmentEngine.cpp
    src/core/WebUiProbe.cpp
    src/core/LocalProcessResolver.cpp
    src/core/DeviceClassifier.cpp
    src/core/RiskAnalyzer.cpp
    src/core/BaselineStore.cpp
    src/core/ReportExporter.cpp
    src/core/HostMonitor.cpp
    src/core/ThreadPool.cpp
    src/core/Stopwatch.cpp)

add_library(netlens_engine STATIC ${ENGINE_SOURCES})
target_include_directories(netlens_engine
    PUBLIC  include
    PRIVATE src)

# The engine pulls in the standard Win32 libraries. Listed as PUBLIC so
# the consuming executable (NetLens.exe in this tree) inherits the link
# automatically.
if (WIN32)
    target_link_libraries(netlens_engine PUBLIC
        ws2_32 iphlpapi shlwapi user32 advapi32 ole32 winhttp netapi32)
endif()

# Where the resulting .lib lands.
set_target_properties(netlens_engine PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/lib")

# Install rule — `cmake --install` produces
# `${dst}/lib/netlens_engine.lib` + `${dst}/include/...`.
include(GNUInstallDirs)
install(TARGETS netlens_engine ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
