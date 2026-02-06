cmake_minimum_required(VERSION 3.16)
project(ThreaDolphin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt6 setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# Find libpcap
find_library(PCAP_LIBRARY pcap REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
)

set(HEADERS
    src/MainWindow.h
)

# Create executable
add_executable(ThreaDolphin ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(ThreaDolphin
    Qt6::Core
    Qt6::Widgets
    ${PCAP_LIBRARY}
)

# Include directories
target_include_directories(ThreaDolphin PRIVATE src)