cmake_minimum_required(VERSION 3.20)
project("HookTool")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")

add_subdirectory(lib/MinHook)

include_directories(common)
add_subdirectory(launcher)
add_subdirectory(clientdll)