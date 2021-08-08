cmake_minimum_required(VERSION 3.5)
project(drogon_assist)

list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(BOTAN2 REQUIRED)
find_package(Drogon REQUIRED)

add_library(drogon_assist STATIC
	drogon/assist/passwdhash.cpp
	drogon/assist/http_signature.cpp
	drogon/assist/crypto/Sha3.cpp
	drogon/assist/crypto/Blake2b.cpp
	drogon/assist/hash.cpp
	drogon/assist/plugin/ParameterPollutionProtector.cpp
	drogon/assist/plugin/BOMRemover.cpp
	drogon/assist/basic_auth.cpp)

target_link_libraries(drogon_assist PUBLIC ${BOTAN2_LIBRARIES} ${DROGON_LIBRARIES} bsd)
target_include_directories(drogon_assist PUBLIC ${BOTAN2_INCLUDE_DIRS} ${DROGON_INCLUDE_DIRS})

include_directories(.)
option(BUILD_EXAMPLE "Build Drogon Assist examples" ON)
option(BUILD_TESTS "Build Drogon Assist tests" ON)

set(DROGON_ASSIST_HEADERS
	drogon/assist/hash.hpp
	drogon/assist/passwdhash.hpp
	drogon/assist/http_signature.cpp
	drogon/assist/plugin/ParameterPollutionProtector.hpp
	drogon/assist/plugin/BOMRemover.hpp
)

if(BUILD_EXAMPLE)
	add_subdirectory(example)
endif()
if(BUILD_TESTS)
	add_subdirectory(tests)
endif()

install(FILES ${DROGON_ASSIST_HEADERS} DESTINATION ${INSTALL_INCLUDE_DIR}/drogon)
