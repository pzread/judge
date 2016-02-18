cmake_minimum_required (VERSION 3.0)

project(pyext CXX)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-std=c++14 COMPILER_SUPPORTS_CXX14)
if(COMPILER_SUPPORTS_CXX14)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support. Please use a different C++ compiler.")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden")

include_directories(pyext inc)
add_library(pyext SHARED src/pyext.cpp src/core.cpp src/utils.cpp src/sandbox.cpp)
target_link_libraries(pyext uv cgroup)
