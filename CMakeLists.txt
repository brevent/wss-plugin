cmake_minimum_required(VERSION 3.16)

project(wss-plugin C)

find_package(libwebsockets 4.1.0 QUIET)
if(NOT libwebsockets_FOUND)
    find_package(Libwebsockets 3.2.0 REQUIRED)
endif()

find_library(LWS_LIBRARIES websockets)
if(NOT EXISTS ${LWS_LIBRARIES} OR ${LWS_LIBRARIES} MATCHES "\\.a$")
    set(LWS_LIBRARIES websockets)
endif()
message("LWS_LIBRARIES: ${LWS_LIBRARIES}")
add_executable(wss-plugin-client wss-plugin-client.c)
target_link_libraries(wss-plugin-client ${LWS_LIBRARIES})
install(TARGETS wss-plugin-client DESTINATION bin)
