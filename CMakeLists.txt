cmake_minimum_required(VERSION 3.17.0 FATAL_ERROR)

project(densityapp)
set(PACKAGE_VERSION "1.0")

#
# Build settings
#

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR
    "In-source builds are not allowed. Please clean your source tree and try again.")
endif()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build" FORCE)
endif()

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/install" CACHE PATH "Install directory" FORCE)
endif()

message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMake version: ${CMAKE_VERSION}")
message(STATUS "CMake generator: ${CMAKE_GENERATOR}")

# Add path for custom modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Generate compile_commands.json, used by clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

option(CREATE_DOCUMENTATION "Create Documentation" OFF)

include(HandleOptions)

add_subdirectory(src)

set(CORE_FOUND TRUE)
set(CORE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/inc")


if(CREATE_DOCUMENTATION)
  # Doxygen
  message(STATUS "Creating documentation")
  add_custom_target(doc DEPENDS doxygen-etl)
endif()
