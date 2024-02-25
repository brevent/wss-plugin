cmake_minimum_required(VERSION 3.0)

project(wss-plugin-client C)

find_package(libwebsockets REQUIRED)

add_executable(wss-plugin-client wss-plugin-client.c)

target_link_libraries(wss-plugin-client websockets ${LIBWEBSOCKETS_DEP_LIBS})

install(TARGETS wss-plugin-client DESTINATION bin)
