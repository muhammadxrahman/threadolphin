cmake_minimum_required(VERSION 3.16)
project(ThreaDolphin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC-specific flags for C++17
if(MSVC)
    add_compile_options(/Zc:__cplusplus)
endif()

# Qt6 setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# Find libpcap/Npcap - Platform specific
if(WIN32)
    # Windows: Use Npcap
    set(NPCAP_SDK_DIR "C:/npcap-sdk-1.16" CACHE PATH "Path to Npcap SDK")
    
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        PATHS ${NPCAP_SDK_DIR}/Include
    )
    
    find_library(PCAP_LIBRARY
        NAMES wpcap
        PATHS ${NPCAP_SDK_DIR}/Lib/x64
    )
    
    find_library(PACKET_LIBRARY
        NAMES Packet
        PATHS ${NPCAP_SDK_DIR}/Lib/x64
    )
    
    if(NOT PCAP_LIBRARY OR NOT PACKET_LIBRARY)
        message(FATAL_ERROR "Npcap SDK not found. Please install Npcap SDK and set NPCAP_SDK_DIR")
    endif()
    
    message(STATUS "Found Npcap: ${PCAP_LIBRARY}")
else()
    # macOS/Linux: Use libpcap
    find_library(PCAP_LIBRARY pcap REQUIRED)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/PacketCapture.cpp
    src/CaptureThread.cpp
    src/PacketModel.cpp
    src/PacketParser.cpp
    src/SettingsDialog.cpp
    src/StreamWindow.cpp
)

set(HEADERS
    src/MainWindow.h
    src/PacketCapture.h
    src/CaptureThread.h
    src/Packet.h
    src/PacketModel.h
    src/PacketParser.h
    src/SettingsDialog.h
    src/StreamIdentifier.h
    src/StreamWindow.h
)

# Create executable
if(APPLE)
    # Set app icon for macOS
    set(MACOSX_BUNDLE_ICON_FILE ThreaDolphin.icns)
    set(APP_ICON_MACOSX ${CMAKE_CURRENT_SOURCE_DIR}/resources/ThreaDolphin.icns)
    set_source_files_properties(${APP_ICON_MACOSX} PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources")
    
    add_executable(ThreaDolphin MACOSX_BUNDLE ${SOURCES} ${HEADERS} ${APP_ICON_MACOSX})
    
    # Set macOS bundle properties
    set_target_properties(ThreaDolphin PROPERTIES
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.threadolphin.app"
        MACOSX_BUNDLE_BUNDLE_NAME "ThreaDolphin"
        MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0"
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/resources/Info.plist.in
    )
elseif(WIN32)
    # Windows executable
    add_executable(ThreaDolphin WIN32 ${SOURCES} ${HEADERS})
else()
    # Linux executable
    add_executable(ThreaDolphin ${SOURCES} ${HEADERS})
endif()

# Link libraries
if(WIN32)
    target_link_libraries(ThreaDolphin
        Qt6::Core
        Qt6::Widgets
        ${PCAP_LIBRARY}
        ${PACKET_LIBRARY}
        ws2_32  # Windows Sockets
    )
    
    target_include_directories(ThreaDolphin PRIVATE
        src
        ${PCAP_INCLUDE_DIR}
    )
else()
    target_link_libraries(ThreaDolphin
        Qt6::Core
        Qt6::Widgets
        ${PCAP_LIBRARY}
    )
    
    target_include_directories(ThreaDolphin PRIVATE src)
endif()