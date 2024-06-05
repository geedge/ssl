cmake_minimum_required (VERSION 3.10)

project(${lib_name}_test)

include(ExternalProject)
#### Protoco_test_run


ExternalProject_Add(ProtoTest PREFIX ProtoTest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/test_protocol_run.zip
        URL_MD5 7e9f0f8345ca83665b4314cddc06ea96  
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/${lib_name}/${lib_name}.conf <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/conflist.inf <SOURCE_DIR>/plug/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/${lib_name}.inf <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/business/${lib_name}_test_plug/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/test/${lib_name}_test_plug.inf <SOURCE_DIR>/plug/business/${lib_name}_test_plug/)

ExternalProject_Get_Property(ProtoTest INSTALL_DIR)
ExternalProject_Get_Property(ProtoTest SOURCE_DIR)
set(PROTO_TEST_RUN_DIR ${SOURCE_DIR})

add_executable(proto_test_main IMPORTED GLOBAL)
add_dependencies(proto_test_main ProtoTest)
set_property(TARGET proto_test_main PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/plugin_test_main)


add_library(${lib_name}_test_plug SHARED ${lib_name}_test_plug.cpp)
target_link_libraries(${lib_name}_test_plug MESA_prof_load cjson)
set_target_properties(${lib_name}_test_plug  PROPERTIES PREFIX "")

add_test(NAME COPY_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/${lib_name}.so ${PROTO_TEST_RUN_DIR}/plug/protocol/${lib_name}/${lib_name}.so")
add_test(NAME COPY_TEST_SO COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}_test_plug.so ${PROTO_TEST_RUN_DIR}/plug/business/${lib_name}_test_plug/${lib_name}_test_plug.so")

add_test(NAME RUN_SSL_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ssl/ssl_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ssl -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_E21_BUG_E21_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/e21/ssl_e21_target_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/e21/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_E21_BUG_XXG_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/xxg/ssl_xxg_target_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/xxg/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
