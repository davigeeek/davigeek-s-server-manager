cmake_minimum_required(VERSION 3.16)
project(servermanager CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(httplib GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git GIT_TAG v0.18.3)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(httplib json)

find_package(Threads REQUIRED)
add_executable(servermanager src/main.cpp)
target_link_libraries(servermanager PRIVATE httplib::httplib nlohmann_json::nlohmann_json Threads::Threads)

add_custom_command(TARGET servermanager POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/web $<TARGET_FILE_DIR:servermanager>/web)
