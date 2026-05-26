cmake_minimum_required(VERSION 3.20)

# -----------------------------------------------------------------------------
# NetLens — pure Win32 + C++20. Single self-contained executable.
# No external UI libraries. Engine lives in engine/ and links statically.
# -----------------------------------------------------------------------------

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" NETLENS_VERSION LIMIT_COUNT 1)
string(STRIP "${NETLENS_VERSION}" NETLENS_VERSION)
if (NOT NETLENS_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got: ${NETLENS_VERSION}")
endif()
string(REPLACE "." ";" NETLENS_VERSION_PARTS "${NETLENS_VERSION}")
list(GET NETLENS_VERSION_PARTS 0 NETLENS_VERSION_MAJOR)
list(GET NETLENS_VERSION_PARTS 1 NETLENS_VERSION_MINOR)
list(GET NETLENS_VERSION_PARTS 2 NETLENS_VERSION_PATCH)
message(STATUS "NetLens version: ${NETLENS_VERSION}")

project(NetLens
    VERSION     "${NETLENS_VERSION}"
    DESCRIPTION "NetLens — portable LAN scanner"
    LANGUAGES   CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT — no vcruntime/msvcp DLL deps
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (MSVC)
    add_compile_options(
        /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc
        /GR-                          # no RTTI
        /Zc:inline
        /Gy /Gw
    )
    add_compile_options(
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Os>
        $<$<CONFIG:Release>:/Oy>
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/Ob3>
        $<$<CONFIG:Release>:/GL>
    )
    add_compile_definitions(
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00
        _CRT_SECURE_NO_WARNINGS
        $<$<CONFIG:Release>:_HAS_ITERATOR_DEBUGGING=0>
        $<$<CONFIG:Release>:_ITERATOR_DEBUG_LEVEL=0>
    )
    add_link_options(
        $<$<CONFIG:Release>:/LTCG>
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
        $<$<CONFIG:Release>:/INCREMENTAL:NO>
        /SUBSYSTEM:WINDOWS
        /MANIFEST:NO       # we embed app.manifest via app.rc — don't auto-generate
    )
endif()

# Engine: builds as a STATIC library and PUBLIC-links the Win32 libs it
# needs — those propagate to NetLens automatically via
# target_link_libraries.
add_subdirectory(engine)

set(NETLENS_SOURCES
    src/main.cpp
    src/App.cpp
    src/MainWindow.cpp
    src/Capture.cpp
    src/Theme.cpp
    src/Dpi.cpp
    src/Controls/StatCard.cpp
    src/Controls/HostTable.cpp
    src/Controls/DetailsPanel.cpp
    src/Dialogs/AboutDialog.cpp
    src/Dialogs/AdaptersDialog.cpp
    src/Dialogs/SettingsDialog.cpp
    src/Dialogs/PortListsDialog.cpp
    # headers — listed so IDEs pick them up
    src/App.h
    src/MainWindow.h
    src/Capture.h
    src/Theme.h
    src/Models.h
    src/Dpi.h
    src/Controls/StatCard.h
    src/Controls/HostTable.h
    src/Controls/DetailsPanel.h
    src/Dialogs/AboutDialog.h
    src/Dialogs/AdaptersDialog.h
    src/Dialogs/SettingsDialog.h
    src/Dialogs/PortListsDialog.h
    Resource.h
    app.rc
)

add_executable(NetLens WIN32 ${NETLENS_SOURCES})

target_include_directories(NetLens PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_definitions(NetLens PRIVATE
    NETLENS_VERSION_STR="${NETLENS_VERSION}"
    NETLENS_VERSION_MAJOR=${NETLENS_VERSION_MAJOR}
    NETLENS_VERSION_MINOR=${NETLENS_VERSION_MINOR}
    NETLENS_VERSION_PATCH=${NETLENS_VERSION_PATCH})

# RC files inherit target_compile_definitions and target_include_directories
# (CMake >= 3.20).
target_link_libraries(NetLens PRIVATE
    netlens_engine
    user32 gdi32 comctl32 comdlg32 shell32 advapi32 ole32 msimg32 uxtheme
    gdiplus)   # PNG save for Ctrl+T captures

set_target_properties(NetLens PROPERTIES
    OUTPUT_NAME              "NetLens"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
