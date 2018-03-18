set(ENV{STAGING_DIR} .)
set(CMAKE_C_COMPILER mips-openwrt-linux-gcc)
set(CMAKE_CXX_COMPILER mips-openwrt-linux-g++)
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})
link_directories(./lib/mips)

