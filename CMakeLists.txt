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

find_package(Git)
if(GIT_FOUND)
    message("Git found: ${GIT_EXECUTABLE}")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_DESCRIBE_RESULT
        OUTPUT_VARIABLE GIT_DESCRIBE_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT ${GIT_DESCRIBE_RESULT})
        add_definitions(-DWSS_PLUGIN_VERSION="${GIT_DESCRIBE_OUTPUT}")
    endif()
endif()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${LWS_LIBRARIES})
check_function_exists(lws_get_opcode HAVE_LWS_GET_OPCODE)
if (HAVE_LWS_GET_OPCODE)
    add_definitions(-DHAVE_LWS_GET_OPCODE)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

add_executable(wss-plugin-client wss-plugin-client.c common.c)
target_link_libraries(wss-plugin-client ${LWS_LIBRARIES})
install(TARGETS wss-plugin-client DESTINATION bin)

add_executable(wss-plugin-server wss-plugin-server.c common.c)
target_link_libraries(wss-plugin-server ${LWS_LIBRARIES})
install(TARGETS wss-plugin-server DESTINATION bin)