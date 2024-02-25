cmake_minimum_required(VERSION 3.0)

project(wss-plugin-client C)

find_library(LWS_LIBRARY websockets)

add_executable(wss-plugin-client wss-plugin-client.c)

target_link_libraries(wss-plugin-client websockets)

install(TARGETS wss-plugin-client DESTINATION bin)
