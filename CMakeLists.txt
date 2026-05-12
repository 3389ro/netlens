cmake_minimum_required(VERSION 3.20)

# -----------------------------------------------------------------------------
# NetLens - Portable LAN Scanner for Small Business Networks
# Native C++20 / Win32 GUI + CLI. No external dependencies.
# -----------------------------------------------------------------------------

project(NetLens
    VERSION 1.2.0
    DESCRIPTION "Portable LAN scanner for small business networks"
    LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ship a single self-contained .exe — no MSVC runtime DLLs needed on target machines.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    add_compile_definitions(
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00            # Windows 10
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS)
    # Release defaults: optimised, no debug symbols in the binary
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG /Oy /GL")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
endif()

# -----------------------------------------------------------------------------
# Source files
# -----------------------------------------------------------------------------

set(CORE_SOURCES
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
    src/core/VendorPortProfiles.cpp
    src/core/UdpProbes.cpp
    src/core/OuiData.cpp
    src/core/ServiceDetector.cpp
    src/core/RiskAnalyzer.cpp
    src/core/BaselineStore.cpp
    src/core/ReportExporter.cpp
    src/core/HostMonitor.cpp
    src/core/ThreadPool.cpp
    src/core/Stopwatch.cpp)

set(CORE_HEADERS
    src/AppConstants.h
    src/Models.h
    src/core/NetworkAdapterService.h
    src/core/IpAddressUtils.h
    src/core/IpRangeParser.h
    src/core/ScanPresetService.h
    src/core/NetworkScanner.h
    src/core/PingService.h
    src/core/PortScanner.h
    src/core/DnsResolver.h
    src/core/MacResolver.h
    src/core/VendorResolver.h
    src/core/VendorPortProfiles.h
    src/core/UdpProbes.h
    src/core/OuiData.h
    src/core/ServiceDetector.h
    src/core/RiskAnalyzer.h
    src/core/BaselineStore.h
    src/core/ReportExporter.h
    src/core/HostMonitor.h
    src/core/ThreadPool.h
    src/core/Stopwatch.h)

set(CLI_SOURCES
    src/cli/CliApp.cpp
    src/cli/CommandLineParser.cpp)
set(CLI_HEADERS
    src/cli/CliApp.h
    src/cli/CommandLineParser.h)

set(GUI_SOURCES
    src/gui/GuiApp.cpp
    src/gui/MainWindow.cpp
    src/gui/MonitorWindow.cpp
    src/gui/GuiControls.cpp
    src/gui/GuiLayout.cpp
    src/gui/GuiUtils.cpp)
set(GUI_HEADERS
    src/gui/GuiApp.h
    src/gui/MainWindow.h
    src/gui/MonitorWindow.h
    src/gui/GuiControls.h
    src/gui/GuiLayout.h
    src/gui/GuiUtils.h)

set(RESOURCE_FILES
    src/resources/resource.h
    src/resources/app.rc
    src/resources/NetLens.manifest)

add_executable(NetLens WIN32
    src/main.cpp
    ${CORE_SOURCES}  ${CORE_HEADERS}
    ${CLI_SOURCES}   ${CLI_HEADERS}
    ${GUI_SOURCES}   ${GUI_HEADERS}
    ${RESOURCE_FILES})

target_include_directories(NetLens PRIVATE src)

# Required Windows libraries — nothing external.
target_link_libraries(NetLens PRIVATE
    ws2_32
    iphlpapi
    comctl32
    shlwapi
    user32
    gdi32
    comdlg32
    advapi32
    shell32
    ole32
    winhttp)

# GUI subsystem — the OS never allocates a console for this process, so the
# GUI launch is truly flash-free (no black rect on the left while wmain
# wakes up). For CLI invocations we AttachConsole(ATTACH_PARENT_PROCESS) in
# main.cpp to plug stdout/stderr into the calling cmd.exe / Windows Terminal,
# falling back to AllocConsole when there isn't a parent terminal.
set_target_properties(NetLens PROPERTIES
    OUTPUT_NAME "NetLens"
    WIN32_EXECUTABLE TRUE
    VS_DPI_AWARE "PerMonitor")

# Our app.rc embeds the manifest explicitly (so we keep ComCtl6 visual styles,
# DPI awareness and asInvoker in one place). Tell MSBuild not to auto-generate
# a second manifest, otherwise the resource compiler errors with CVT1100.
if (MSVC)
    target_link_options(NetLens PRIVATE /MANIFEST:NO)
endif()

# Friendly source groups in Visual Studio.
source_group("src" FILES src/main.cpp src/AppConstants.h src/Models.h)
source_group("src\\core" FILES ${CORE_SOURCES} ${CORE_HEADERS})
source_group("src\\cli" FILES ${CLI_SOURCES} ${CLI_HEADERS})
source_group("src\\gui" FILES ${GUI_SOURCES} ${GUI_HEADERS})
source_group("src\\resources" FILES ${RESOURCE_FILES})
