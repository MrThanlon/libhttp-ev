cmake_minimum_required(VERSION 3.18)
project(http-ev C)

set(CMAKE_C_STANDARD 11)

file(GLOB_RECURSE SOURCES "src/*.*")
# add_compile_options(-Ofast)
add_library(${PROJECT_NAME} STATIC ${SOURCES})

# dependency
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/;${CMAKE_MODULE_PATH}")
include(FetchContent)
# llhttp
FetchContent_Declare(llhttp URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v6.0.5.tar.gz")
FetchContent_MakeAvailable(llhttp)
# wslay
FetchContent_Declare(wslay URL "https://github.com/tatsuhiro-t/wslay/archive/refs/tags/release-1.1.1.tar.gz")
FetchContent_MakeAvailable(wslay)
# ev
find_package(Libev REQUIRED)
# nettle
find_package(Nettle REQUIRED)

target_include_directories(${PROJECT_NAME} PUBLIC include ${LIBEV_INCLUDE_DIRS} ${NETTLE_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} llhttp wslay ${LIBEV_LIBRARIES} ${NETTLE_LIBRARIES})
