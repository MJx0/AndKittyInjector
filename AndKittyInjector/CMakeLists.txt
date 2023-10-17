cmake_minimum_required(VERSION 3.5)

project(AndKittyInjector)

set(KITTYMEMORY_PATH ../KittyMemoryEx/KittyMemoryEx)
FILE(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)

set(XDL_PATH src/xdl)
FILE(GLOB XDL_SRC ${XDL_PATH}/*.c)

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0 -g -std=c++20 -DDEBUG -DkNO_KEYSTONE")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O2 -s -std=c++20 -DNDEBUG -DkNO_KEYSTONE")

FILE(GLOB PROJ_SRC src/*.cpp src/Injector/*.cpp)

add_executable(AndKittyInjector ${PROJ_SRC} ${KITTYMEMORY_SRC} ${XDL_SRC})

target_include_directories(AndKittyInjector PUBLIC ${KITTYMEMORY_PATH} ${XDL_PATH})
target_link_libraries(AndKittyInjector -llog)