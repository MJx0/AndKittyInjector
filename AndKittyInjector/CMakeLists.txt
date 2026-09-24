cmake_minimum_required(VERSION 3.16)

project(AndKittyInjector
    VERSION 1.0
    LANGUAGES CXX
)

# -----------------------------
# Options
# -----------------------------
option(KT_DISABLE_KEYSTONE "Disable keystone support" ON)

# -----------------------------
# C++ standard
# -----------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------
# KittyMemoryEx library
# -----------------------------
set(KITTYMEMORY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../KittyMemoryEx/KittyMemoryEx")
file(GLOB KITTYMEMORY_SRC "${KITTYMEMORY_PATH}/*.cpp")
set(KEYSTONE_LIB ${KITTYMEMORY_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)

# -----------------------------
# Project sources
# -----------------------------
file(GLOB PROJ_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Injector/*.cpp"
)

# -----------------------------
# Executable
# -----------------------------
add_executable(AndKittyInjector
    ${PROJ_SRC}
    ${KITTYMEMORY_SRC}
)

# -----------------------------
# Includes
# -----------------------------
target_include_directories(AndKittyInjector
    PRIVATE
        ${KITTYMEMORY_PATH}
)

# -----------------------------
# Compile definitions
# -----------------------------
target_compile_definitions(AndKittyInjector
    PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
        $<$<BOOL:${KT_DISABLE_KEYSTONE}>:kNO_KEYSTONE>
)

# -----------------------------
# Compile options
# -----------------------------
target_compile_options(AndKittyInjector
    PRIVATE
        $<$<CONFIG:Debug>:-O0 -g>
        $<$<CONFIG:Release>:-O2 -ffunction-sections -fdata-sections>
        -Wall
        -Wextra
        -Werror
        -fexceptions
        -Wno-unused-command-line-argument
)

# -----------------------------
# Platform-specific libraries
# -----------------------------
target_link_options(AndKittyInjector
    PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:Release>:-Wl,--strip-all>
)

if(ANDROID)
    target_link_libraries(AndKittyInjector PRIVATE log $<$<NOT:$<BOOL:${KT_DISABLE_KEYSTONE}>>:${KEYSTONE_LIB}>)
endif()