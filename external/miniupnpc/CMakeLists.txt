cmake_minimum_required(VERSION 3.12)
project(miniupnpc_static_only LANGUAGES C)

# Force static lib
set(BUILD_SHARED_LIBS OFF)

# ---- Sources from your Makefile (2009 set) ----
# If your files are under src/, prepend src/ to each.
set(MINIUPNPC_SOURCES
    igd_desc_parse.c
    miniupnpc.c
    minixml.c
    minisoap.c
    miniwget.c
    upnpcommands.c
    upnpreplyparse.c
    # minissdpc.c
    minissdpc_stub.c
    upnperrors.c
)

add_library(miniupnpc STATIC ${MINIUPNPC_SOURCES})

# Public headers directory (so consumers can #include "miniupnpc.h" etc.)
target_include_directories(miniupnpc
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(WIN32)
  target_compile_definitions(miniupnpc PRIVATE NDEBUG STATICLIB)
else()
  target_compile_definitions(miniupnpc PRIVATE NDEBUG STATICLIB MINIUPNPC_SET_SOCKET_TIMEOUT)
endif()

# Windows needs Winsock
if (WIN32)
  target_link_libraries(miniupnpc PRIVATE ws2_32)
endif()

# Optional: set output name like libminiupnpc.a / miniupnpc.lib
set_target_properties(miniupnpc PROPERTIES OUTPUT_NAME "miniupnpc")

# Optional install
# include(GNUInstallDirs)
# install(TARGETS miniupnpc ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
# install(FILES miniupnpc.h miniwget.h upnpcommands.h igd_desc_parse.h
#               upnpreplyparse.h upnperrors.h declspec.h
#         DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/miniupnpc)
