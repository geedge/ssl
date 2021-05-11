cmake_minimum_required (VERSION 2.8)

set(lib_name ssl)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

SET(CMAKE_C_COMPILER "/usr/bin/g++")
set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN


include_directories(/opt/MESA/include/MESA/)
include_directories(./src/inc/)
include_directories(./src/)

file(GLOB SRC
    "src/*.c"
    "src/*.cpp"
)

set(DNS_DEPEND_DYN_LIB MESA_handle_logger MESA_field_stat2 MESA_prof_load)

# Shared Library Output
add_library(ssl SHARED ${SRC})
set_target_properties(ssl  PROPERTIES PREFIX "")
target_link_libraries(ssl ${DNS_DEPEND_DYN_LIB})
#target_link_libraries(ssl "openssl.so")
if(DEFINED MESA_SHARED_INSTALL_DIR)
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name} LIBRARY_OUTPUT_DIRECTORY ${MESA_SHARED_INSTALL_DIR})
else()
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name})
endif()

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run/)

set(CPACK_RPM_LIBRARIES_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/plug/protocol/ssl/ssl.inf"
                                         "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/ssl/ssl.conf")

SET(CPACK_RPM_LIBRARIES_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/preInstall.sh")
SET(CPACK_RPM_LIBRARIES_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/preUninstall.sh")

install(TARGETS ssl LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name} COMPONENT LIBRARIES)
install(FILES bin/${lib_name}.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name} COMPONENT PROFILE)
install(FILES bin/${lib_name}/${lib_name}.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/conf/${lib_name}/ COMPONENT PROFILE)
install(FILES src/${lib_name}.h DESTINATION /opt/MESA/include/MESA COMPONENT HEADER)

file(GLOB DEMO
    "test/src/*.c"
)

include(Package)
