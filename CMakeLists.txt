cmake_minimum_required(VERSION 3.10)
project(SimpleUdp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(SimpleUdp STATIC udp/simple_udp.cpp udp/simple_udp.h)

target_include_directories(SimpleUdp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(SimpleUdp PROPERTIES PUBLIC_HEADER "udp/simple_udp.h")

add_executable(SimpleUdpExample examples/udp_echo_server_example.cpp)
target_link_libraries(SimpleUdpExample PRIVATE SimpleUdp)
