cmake_minimum_required (VERSION 3.0)

set(lib_name ssl)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

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

find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
if (CMAKE_CXX_CPPCHECK)
    list(
        APPEND CMAKE_CXX_CPPCHECK 
            "--enable=all"
            "--error-exitcode=1"
            "--suppress=unusedFunction"
            "--suppress=missingInclude"
            "--suppress=uselessAssignmentPtrArg"
            "--suppress=unmatchedSuppression"
            "--suppress=unreadVariable"
            "--suppress=unreachableCode"
            "--suppress=constParameter"
            "--suppress=variableScope"
            "--suppress=*:${PROJECT_SOURCE_DIR}/src/utstring.h"
    )
  message("cppcheck start...")
else()
  message(FATAL_ERROR "Could not find the program cppcheck.")
endif()

include_directories(/opt/MESA/include/MESA/)
include_directories(include)

add_subdirectory(support)

file(GLOB SRC
    "src/*.c"
    "src/*.cpp"
)

set(DEPEND_DYN_LIB MESA_handle_logger fieldstat4 MESA_prof_load)

SET_SOURCE_FILES_PROPERTIES(${SRC} PROPERTIES LANGUAGE CXX )

# Shared Library Output
add_library(ssl SHARED ${SRC})
set_target_properties(ssl  PROPERTIES PREFIX "")
target_link_libraries(ssl ${DEPEND_DYN_LIB} -Wl,--no-whole-archive openssl-crypto-static -Wl,--no-whole-archive openssl-ssl-static)
#target_link_libraries(ssl "openssl.so")
if(DEFINED MESA_SHARED_INSTALL_DIR)
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name} LIBRARY_OUTPUT_DIRECTORY ${MESA_SHARED_INSTALL_DIR})
else()
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name})
endif()

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run/)

enable_testing()
add_subdirectory(test)

set(CPACK_RPM_LIBRARIES_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/plug/protocol/ssl/ssl.inf"
                                         "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/ssl/ssl.conf")

SET(CPACK_RPM_LIBRARIES_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/preInstall.sh")
SET(CPACK_RPM_LIBRARIES_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/preUninstall.sh")

install(TARGETS ssl LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name} COMPONENT LIBRARIES)
install(FILES bin/${lib_name}.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name} COMPONENT PROFILE)
install(FILES bin/${lib_name}/${lib_name}.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/conf/${lib_name}/ COMPONENT PROFILE)
install(FILES include/${lib_name}.h DESTINATION /opt/MESA/include/MESA COMPONENT HEADER)

file(GLOB DEMO
    "test/src/*.c"
)

include(Package)
