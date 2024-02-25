cmake_minimum_required(VERSION 3.16)

project(wss-plugin C)

find_package(libwebsockets 4.1.0 CONFIG QUIET)
if(NOT libwebsockets_FOUND)
    find_package(Libwebsockets 3.2.0 CONFIG REQUIRED)
endif()

add_executable(wss-plugin-client wss-plugin-client.c)
target_link_libraries(wss-plugin-client websockets)
install(TARGETS wss-plugin-client DESTINATION bin)
