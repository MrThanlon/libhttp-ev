cmake_minimum_required(VERSION 3.18)
# project(http-ev C)
project(http-ev)

set(CMAKE_CXX_STANDARD 11)
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

add_library(${PROJECT_NAME} STATIC ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC /usr/local/include)
target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)
target_link_libraries(${PROJECT_NAME} llhttp ev wslay nettle)

# test
enable_testing()
find_package(GTest REQUIRED)

add_executable(test-${PROJECT_NAME} test/test.cpp)
# target_compile_options(test-${PROJECT_NAME} PUBLIC --coverage)
target_link_libraries(test-${PROJECT_NAME} ${GTEST_BOTH_LIBRARIES} ${PROJECT_NAME})
target_include_directories(test-${PROJECT_NAME} PUBLIC ${GTEST_INCLUDE_DIRS} src)
include(CMakeCXXInformation)
include(GoogleTest)
gtest_discover_tests(test-${PROJECT_NAME})
