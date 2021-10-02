cmake_minimum_required(VERSION 3.20)
project(http-ev C)

set(CMAKE_C_STANDARD 11)
include(FetchContent)
FetchContent_Declare(llhttp URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v6.0.5.tar.gz")
FetchContent_MakeAvailable(llhttp)

file(GLOB_RECURSE SOURCES "src/*.*")
# add_compile_options(-Ofast)

# add_library(http-ev src/http.c src/parser.c src/parser.h src/context.c src/context.h src/event_callback.c src/event_callback.h)
add_library(http-ev ${SOURCES})
target_include_directories(http-ev PUBLIC /usr/local/include)
target_link_directories(http-ev PUBLIC /usr/local/lib)
target_link_libraries(http-ev llhttp ev)
