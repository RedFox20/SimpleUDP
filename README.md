# Simple UDP Library for POSIX sockets
This is a minimal low-level wrapper of POSIX and Winsock sockets, tested on Ubuntu 24.04 LTS and Windows 11.

# Usage
1. Clone this repository to your main project, e.g. `libs/SimpleUDP`
2. Add to CMake: `add_subdirectory(libs/SimpleUDP)`
3. Link to your target: `target_link_libraries(your_target SimpleUDP)`
4. Include the header in your source files: `#include <udp/simple_udp.h>`

# Testing this library locally
1. Build the library: `cmake -B build && cmake --build build`
2. Run the test example: `./build/SimpleUdpExample` or `build/Debug/SimpleUdpExample.exe`

# License
This project is licensed under the MIT License.
