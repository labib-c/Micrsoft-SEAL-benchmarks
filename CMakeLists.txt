cmake_minimum_required(VERSION 3.11)

project(sealproject VERSION 1.0)

set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Available Build types
set(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release Tsan)

# -------------------------------
# Libraries
# -------------------------------

find_package(SEAL 4.0.0 REQUIRED)

# -------------------------------
# Compile Flags 
# -------------------------------

# set ASAN options for debug builds
set(ENV{ASAN_OPTIONS} "\ 
  detect_leaks=0:\ 
  strict_string_checks=1:\
  detect_stack_use_after_return=1:\
  check_initialization_order=1:\
  strict_init_order=1:\
  detect_invalid_pointer_pairs=2"
)

# Debug builds
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} \
  -fsanitize=address \
  -fno-omit-frame-pointer \
  -fsanitize=undefined \
  -fsanitize=float-divide-by-zero \
  -fsanitize=float-cast-overflow \
  -fno-optimize-sibling-calls \
  -g"
)
set (CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} \
  -fsanitize=address,undefined \
  -g"
)

# Tsan builds
set (CMAKE_CXX_FLAGS_TSAN "\
  -fsanitize=thread \
  -g"
)
set (CMAKE_EXE_LINKER_FLAGS_TSAN "\
  -fsanitize=thread \
  -g"
)

add_executable(sealproject 
  ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
)

target_compile_options(sealproject 
  PRIVATE
  -Wall 
  -Wextra 
  -fstack-protector-strong 
  -fPIE
)

target_link_libraries(sealproject
  PRIVATE 
  SEAL::seal
)
