# Builds the two C++17 consumers of the C ABI against the cdylib cargo
# produced. It deliberately does not run cargo: the library is built with
# --locked by the caller (CI, or the commands in rust/ffi/README.md), and
# pointing CMake at the result keeps the two build systems from arguing about
# profiles.
#
#   cargo build --locked --manifest-path rust/ffi/Cargo.toml
#   cmake -S rust/ffi/examples/cpp -B rust/ffi/target/cppbuild
#   cmake --build rust/ffi/target/cppbuild --config Debug
#   rust/ffi/target/cppbuild/bin/aprv_conformance <manifest dir>
#
# APRV_LIB_DIR defaults to rust/ffi/target/debug, cargo's own output
# directory for this crate. Override it when CARGO_TARGET_DIR is set
# elsewhere.

cmake_minimum_required(VERSION 3.16)
project(aprv_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED APRV_LIB_DIR)
  set(APRV_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/debug")
endif()
get_filename_component(APRV_LIB_DIR "${APRV_LIB_DIR}" ABSOLUTE)

# One place for the executables in every generator. Visual Studio is
# multi-config and would otherwise bury them under Debug/ or Release/, so a
# CI step that knows where to find them on Linux would not on Windows.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
foreach(configuration IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${configuration} "${CMAKE_BINARY_DIR}/bin")
endforeach()

# On MSVC cargo names the import library <name>.dll.lib, which find_library
# reaches through the second name below.
find_library(APRV_LIBRARY
  NAMES apple_purchase_receipt_verifier_ffi apple_purchase_receipt_verifier_ffi.dll
  PATHS "${APRV_LIB_DIR}"
  NO_DEFAULT_PATH
  REQUIRED)
message(STATUS "linking against ${APRV_LIBRARY}")

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

function(aprv_add_consumer name source)
  add_executable(${name} ${source})
  target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../include")
  target_link_libraries(${name} PRIVATE "${APRV_LIBRARY}")
  if(WIN32)
    # There is no rpath on Windows: the DLL has to sit beside the executable.
    add_custom_command(TARGET ${name} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${APRV_LIB_DIR}/apple_purchase_receipt_verifier_ffi.dll"
              "$<TARGET_FILE_DIR:${name}>")
  else()
    set_target_properties(${name} PROPERTIES BUILD_RPATH "${APRV_LIB_DIR}")
  endif()
endfunction()

aprv_add_consumer(aprv_conformance conformance.cpp)
aprv_add_consumer(aprv_example example.cpp)
