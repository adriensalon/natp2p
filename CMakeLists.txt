cmake_minimum_required(VERSION 3.12)
project(natp2p)

option(NATP2P_BUILD_TOOL "Build tool executables" ON)

add_subdirectory(external/miniupnpc)
add_subdirectory(external/natpmp)

# natp2p library
add_library(natp2p STATIC "source/natp2p.cpp")
set_target_properties(natp2p PROPERTIES CXX_STANDARD 17)
target_include_directories(natp2p PUBLIC include)
target_link_libraries(natp2p PRIVATE miniupnpc natpmp)

# tools
if(NATP2P_BUILD_TOOL)
    add_executable(natp2p_demo "demo/main.cpp")
    set_target_properties(natp2p_demo PROPERTIES CXX_STANDARD 17)
    target_link_libraries(natp2p_demo natp2p)
endif()
