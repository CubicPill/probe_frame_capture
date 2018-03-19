cmake_minimum_required(VERSION 2.6)
project(radiotap)

add_definitions("-D_BSD_SOURCE -DRADIOTAP_SUPPORT_OVERRIDES")

add_library(radiotap SHARED radiotap.c)
set_target_properties(radiotap PROPERTIES
        COMPILE_FLAGS "-Wall -Wextra")

