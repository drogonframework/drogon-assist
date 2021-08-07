add_executable(drassist_test)

target_sources(drassist_test PRIVATE main.cpp
                                    unittest.cpp
                                    basic_auth_test.cpp
                                    http_signature_test.cpp)
target_link_libraries(drassist_test PRIVATE drogon_assist)