cmake_minimum_required (VERSION 2.8.11)

project (yacas_kernel CXX)

set(YACAS_PREFIX "" CACHE FILEPATH "Yacas installation root")

if(NOT EXISTS ${YACAS_PREFIX}/include/yacas/yacas.h)
  message(SEND_ERROR "Can't find yacas.h in ${YACAS_PREFIX}/include/yacas")
endif()

include_directories (
  "${YACAS_PREFIX}/include"
  )

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -std=c++11")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")
    add_definitions(-DYACAS_NO_CONSTEXPR -DYACAS_NO_ATOMIC_TYPES)
endif ()

find_path (ZEROMQ_INCLUDE_DIR zmq.hpp)
find_library (ZEROMQ_LIBRARY NAMES zmq)

find_path (ZMQPP_INCLUDE_DIR zmqpp.hpp)
find_library (ZMQPP_LIBRARY NAMES zmqpp)

find_path (JSONCPP_INCLUDE_DIR json.h)
find_library (JSONCPP_LIBRARY NAMES jsoncpp)

find_package (OpenSSL)
find_package (Boost REQUIRED program_options)

add_library (libyacas STATIC IMPORTED)

if (MSVC)
    set_target_properties (libyacas PROPERTIES IMPORTED_LOCATION "${YACAS_PREFIX}/lib/yacas.lib")
else ()
    set_target_properties (libyacas PROPERTIES IMPORTED_LOCATION "${YACAS_PREFIX}/lib/libyacas.a")
endif ()
  
add_executable (yacas_kernel src/main.cpp src/yacas_kernel.cpp src/yacas_engine.cpp src/hmac_sha256.cpp)
target_link_libraries (yacas_kernel libyacas ${ZMQPP_LIBRARY} ${ZEROMQ_LIBRARY} ${JSONCPP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} pthread)
