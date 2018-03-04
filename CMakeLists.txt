cmake_minimum_required(VERSION 3.9)
project(probe_frame_capture)

set(CMAKE_C_STANDARD 11)
link_libraries(wpcap)
include_directories(./include)
link_directories(./lib/x64)
add_executable(probe_frame_capture main.c)