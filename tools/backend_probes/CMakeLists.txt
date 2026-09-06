cmake_minimum_required(VERSION 3.21)
project(GhidraBoyBackendProbes LANGUAGES C CXX)

if(NOT IS_DIRECTORY "${MGBA_SOURCE}")
    message(FATAL_ERROR "Pass -DMGBA_SOURCE=<verified mGBA source checkout>")
endif()
set(LIBMGBA_ONLY ON CACHE BOOL "" FORCE)
set(M_CORE_GB ON CACHE BOOL "" FORCE)
set(M_CORE_GBA OFF CACHE BOOL "" FORCE)
set(ENABLE_DEBUGGERS ON CACHE BOOL "" FORCE)
set(ENABLE_GDB_STUB OFF CACHE BOOL "" FORCE)
set(ENABLE_SCRIPTING OFF CACHE BOOL "" FORCE)
add_subdirectory("${MGBA_SOURCE}" mgba)

add_executable(mgba-probe mgba_probe.c)
target_compile_features(mgba-probe PRIVATE c_std_11)
target_include_directories(mgba-probe PRIVATE
    "${MGBA_SOURCE}/include" "${CMAKE_CURRENT_BINARY_DIR}/mgba/include")
# mCore layout depends on the exact library build flags. The generated flags.h
# alone omits late-configured flags (e.g. ENABLE_DIRECTORIES in this revision).
target_compile_definitions(mgba-probe PRIVATE $<TARGET_PROPERTY:mgba,COMPILE_DEFINITIONS>)
find_package(Threads REQUIRED)
target_link_libraries(mgba-probe PRIVATE mgba Threads::Threads)
if(NOT MSVC)
    target_compile_options(mgba-probe PRIVATE -Wall -Wextra -Werror)
endif()
