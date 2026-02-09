cmake_minimum_required(VERSION 3.16)
project(ThreaDolphin VERSION 1.0.0 LANGUAGES CXX)

# Set app icon for macOS
if(APPLE)
    set(MACOSX_BUNDLE_ICON_FILE ThreaDolphin.icns)
    set(APP_ICON_MACOSX ${CMAKE_CURRENT_SOURCE_DIR}/resources/ThreaDolphin.icns)
    set_source_files_properties(${APP_ICON_MACOSX} PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources")
endif()

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
    src/PacketCapture.cpp
    src/CaptureThread.cpp
    src/PacketModel.cpp
    src/PacketParser.cpp
    src/SettingsDialog.cpp
)

set(HEADERS
    src/MainWindow.h
    src/PacketCapture.h
    src/CaptureThread.h
    src/Packet.h
    src/PacketModel.h
    src/PacketParser.h
    src/SettingsDialog.h
)

# Create executable
if(APPLE)
    add_executable(ThreaDolphin MACOSX_BUNDLE ${SOURCES} ${HEADERS} ${APP_ICON_MACOSX})
else()
    add_executable(ThreaDolphin ${SOURCES} ${HEADERS})
endif()

# Set macOS bundle properties
if(APPLE)
    set_target_properties(ThreaDolphin PROPERTIES
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.yourusername.threadolphin"
        MACOSX_BUNDLE_BUNDLE_NAME "ThreaDolphin"
        MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0"
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/resources/Info.plist.in
    )
endif()

# Link libraries
target_link_libraries(ThreaDolphin
    Qt6::Core
    Qt6::Widgets
    ${PCAP_LIBRARY}
)

# Include directories
target_include_directories(ThreaDolphin PRIVATE src)