cmake_minimum_required (VERSION 2.8)

set(lib_name ssl)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)
set(CMAKE_INSTALL_PREFIX /opt/MESA)

#for ASAN
option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_SANITIZE_ADDRESS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

include_directories(/opt/MESA/include/MESA/)
include_directories(./src/inc/)
include_directories(./src/)

file(GLOB SRC
    "src/*.c"    
)

set(DNS_DEPEND_DYN_LIB MESA_handle_logger MESA_field_stat2 MESA_prof_load)

# Shared Library Output
add_library(ssl SHARED ${SRC})
set_target_properties(ssl  PROPERTIES PREFIX "")
target_link_libraries(ssl ${DNS_DEPEND_DYN_LIB})
if(DEFINED MESA_SHARED_INSTALL_DIR)
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name} LIBRARY_OUTPUT_DIRECTORY ${MESA_SHARED_INSTALL_DIR})
else()
	set_target_properties(ssl PROPERTIES OUTPUT_NAME ${lib_name})
endif()


set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp)

install(TARGETS ssl LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name})
install(FILES bin/${lib_name}.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/${lib_name})
install(FILES bin/${lib_name}/${lib_name}.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/conf/${lib_name}/)
install(FILES src/${lib_name}.h DESTINATION /opt/MESA/include/MESA COMPONENT devel)

file(GLOB DEMO
    "test/src/*.c"
)

include(Package)
