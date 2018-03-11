cmake_minimum_required(VERSION 3.7.2)
project(probe_frame_capture)

set(CMAKE_C_STANDARD 11)

include_directories(./include)
if (WIN32)
    link_directories(lib/win/x64)
    link_libraries(wpcap)
else ()
    link_directories(lib/linux/arm64)
    link_libraries(pcap)
endif ()
add_executable(probe_frame_capture capture.c)