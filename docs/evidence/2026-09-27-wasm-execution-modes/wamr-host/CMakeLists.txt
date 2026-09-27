# Spike only (2026-09-27, round 9). WAMR's embedding library, libiwasm.so,
# built from WAMR_ROOT with the WAMR_BUILD_* flags given on the command line
# (scripts/build-wamr.sh passes every one explicitly), plus the aprv-wamr
# host that links it. The layout follows WAMR's own
# product-mini/platforms/linux/CMakeLists.txt (vmlib target, link flags),
# without its defaults: nothing is enabled unless the script asks for it.
cmake_minimum_required(VERSION 3.14)
project(aprv_wamr_host C CXX ASM)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(WAMR_BUILD_PLATFORM "linux")
set(WAMR_BUILD_TARGET "X86_64")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
if(NOT DEFINED WAMR_ROOT)
  message(FATAL_ERROR "pass -DWAMR_ROOT=<WAMR source tree>")
endif()
set(WAMR_ROOT_DIR ${WAMR_ROOT})
if(WAMR_BUILD_JIT EQUAL 1)
  # Ubuntu's llvm-18-dev exports LLVMLineEditor and LLVMDebuginfod with link
  # interfaces on LibEdit::LibEdit and CURL::libcurl, and CMake refuses the
  # whole LLVM package when those targets do not exist (their dev packages
  # are not on this machine). WAMR links neither component; empty targets
  # let find_package(LLVM) load. A link error would show if WAMR needed them.
  add_library(LibEdit::LibEdit INTERFACE IMPORTED)
  add_library(CURL::libcurl INTERFACE IMPORTED)
endif()
include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mindirect-branch-register")

add_library(vmlib SHARED ${WAMR_RUNTIME_LIB_SOURCE})
set_target_properties(vmlib PROPERTIES OUTPUT_NAME iwasm POSITION_INDEPENDENT_CODE ON)
target_link_libraries(vmlib PRIVATE ${LLVM_AVAILABLE_LIBS} -lm -ldl -lpthread)
if(WAMR_BUILD_JIT EQUAL 1)
  # WAMR links every exported LLVM library (LLVM_AVAILABLE_LIBS); LLVMExegesis
  # asks for -lpfm, whose .so link comes from the extracted libpfm4-dev.
  target_link_directories(vmlib PRIVATE ${CMAKE_PREFIX_PATH}/lib/x86_64-linux-gnu)
endif()

add_executable(aprv-wamr host.c)
target_include_directories(aprv-wamr PRIVATE ${WAMR_ROOT_DIR}/core/iwasm/include)
target_link_libraries(aprv-wamr vmlib)
# The host finds libiwasm.so next to itself, and nowhere else.
set_target_properties(aprv-wamr PROPERTIES SKIP_BUILD_RPATH ON)
target_link_options(aprv-wamr PRIVATE "-Wl,-rpath,$ORIGIN")
