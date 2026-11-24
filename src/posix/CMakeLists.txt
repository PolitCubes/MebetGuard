# Linux / macOS: MebetGuard (wrapper) + libMebetGuard.so / .dylib (agent), ТЗ §11.

set(MEBET_POSIX_CFLAGS -Wall -Wextra -Wno-unused-parameter -fstack-protector-strong)

add_library(mebet_agent SHARED
    agent/entry.cpp
    agent/transport.cpp
    "${CMAKE_SOURCE_DIR}/src/common/jvm_guard.cpp")
set_target_properties(mebet_agent PROPERTIES
    OUTPUT_NAME MebetGuard
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)
target_include_directories(mebet_agent PRIVATE agent ${MEBET_JNI_INCLUDES})
target_compile_options(mebet_agent PRIVATE ${MEBET_POSIX_CFLAGS})
target_link_libraries(mebet_agent PRIVATE mebet_common ${CMAKE_DL_LIBS} pthread)
if(APPLE)
    set(MEBET_AGENT_FILE libMebetGuard.dylib)
else()
    set(MEBET_AGENT_FILE libMebetGuard.so)
    target_link_options(mebet_agent PRIVATE -Wl,-z,relro,-z,now -Wl,--no-undefined)
endif()

add_custom_command(
    OUTPUT "${MEBET_GEN}/agent_hash.hpp"
    COMMAND Python3::Interpreter "${CMAKE_SOURCE_DIR}/tools/agent_hash.py" --mode plain
            --file "$<TARGET_FILE:mebet_agent>" --name ${MEBET_AGENT_FILE} --out "${MEBET_GEN}/agent_hash.hpp"
    DEPENDS mebet_agent "${CMAKE_SOURCE_DIR}/tools/agent_hash.py"
    COMMENT "Embedding the agent hash into the wrapper"
    VERBATIM)
add_custom_target(mebet_exe_inputs DEPENDS "${MEBET_GEN}/agent_hash.hpp")

add_executable(mebet_exe exe/main.cpp)
add_dependencies(mebet_exe mebet_exe_inputs)
set_target_properties(mebet_exe PROPERTIES OUTPUT_NAME MebetGuard POSITION_INDEPENDENT_CODE ON)
target_include_directories(mebet_exe PRIVATE "${MEBET_GEN}")
target_compile_options(mebet_exe PRIVATE ${MEBET_POSIX_CFLAGS})
target_link_libraries(mebet_exe PRIVATE mebet_common ${CMAKE_DL_LIBS})
if(NOT APPLE)
    target_link_options(mebet_exe PRIVATE -Wl,-z,relro,-z,now -pie)
endif()
