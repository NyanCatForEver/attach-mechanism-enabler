cmake_minimum_required(VERSION 3.23)

project(attach_mechanism_enabler)
set(CMAKE_CXX_STANDARD 23)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

add_library(attach_mechanism_enabler SHARED library.cc)
target_include_directories(attach_mechanism_enabler
	PRIVATE
	$ENV{JAVA_HOME}/include
	$ENV{JAVA_HOME}/include/win32
	$ENV{JAVA_HOME}/include/linux
	$ENV{JAVA_HOME}/include/darwin
)
target_link_libraries(attach_mechanism_enabler
	PRIVATE
	$ENV{JAVA_HOME}/$<IF:$<PLATFORM_ID:Windows>,lib,jre/lib/amd64/server>/${CMAKE_STATIC_LIBRARY_PREFIX}jvm$<IF:$<PLATFORM_ID:Windows>,${CMAKE_STATIC_LIBRARY_SUFFIX},${CMAKE_SHARED_LIBRARY_SUFFIX}>
	Zydis
)