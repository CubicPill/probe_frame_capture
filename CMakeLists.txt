cmake_minimum_required(VERSION 3.7.2)
project(probe_frame_capture)

set(CMAKE_C_STANDARD 11)

include_directories(./src/headers)

link_libraries(pcap)
add_executable(probe_frame_capture src/capture.c)