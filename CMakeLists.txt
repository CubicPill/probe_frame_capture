cmake_minimum_required(VERSION 3.5.1)
project(probe_frame_capture)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_C_STANDARD 11)

include_directories(./src/headers)

link_libraries(pcap)
add_executable(probe_frame_capture src/headers/capture.h src/capture.c)
add_executable(dump_frames src/dump.c)