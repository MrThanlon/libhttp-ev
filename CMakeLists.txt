cmake_minimum_required(VERSION 3.18)
project(http-ev C)

set(CMAKE_C_STANDARD 11)
include(FetchContent)
# llhttp
FetchContent_Declare(llhttp URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v6.0.5.tar.gz")
FetchContent_MakeAvailable(llhttp)
# wslay
FetchContent_Declare(wslay URL "https://github.com/tatsuhiro-t/wslay/archive/refs/tags/release-1.1.1.tar.gz")
FetchContent_MakeAvailable(wslay)
# TODO: ev
# TODO: nettle

file(GLOB_RECURSE SOURCES "src/*.*")
# add_compile_options(-Ofast)

add_library(${PROJECT_NAME} STATIC ${SOURCES} src/websocket.c src/websocket.h)

target_include_directories(${PROJECT_NAME} PRIVATE /usr/local/include)
target_link_directories(${PROJECT_NAME} PRIVATE /usr/local/lib)
target_link_libraries(${PROJECT_NAME} llhttp ev wslay nettle)
