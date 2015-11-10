cmake_minimum_required (VERSION 3.2.2)

project (yacas_kernel CXX)

set(YACAS_PREFIX "" CACHE FILEPATH "Yacas installation root")

if(NOT EXISTS ${YACAS_PREFIX}/include/yacas/yacas.h)
  message(SEND_ERROR "Can't find yacas.h in ${YACAS_PREFIX}/include/yacas")
endif()

set (YACAS_KERNEL_VERSION_MAJOR 1)
set (YACAS_KERNEL_VERSION_MINOR 0)
set (YACAS_KERNEL_VERSION_MICRO 0)

set (YACAS_KERNEL_VERSION ${YACAS_KERNEL_VERSION_MAJOR}.${YACAS_KERNEL_VERSION_MINOR}.${YACAS_KERNEL_VERSION_MICRO})

configure_file (
  "${PROJECT_SOURCE_DIR}/yacas_kernel_version.hpp.in"
  "${PROJECT_BINARY_DIR}/yacas_kernel_version.hpp"
  )

include_directories (
  "${YACAS_PREFIX}/include"
  "${PROJECT_BINARY_DIR}"
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
find_package (Boost REQUIRED date_time)

add_library (libyacas STATIC IMPORTED)

if (MSVC)
    set_target_properties (libyacas PROPERTIES IMPORTED_LOCATION "${YACAS_PREFIX}/lib/yacas.lib")
else ()
    set_target_properties (libyacas PROPERTIES IMPORTED_LOCATION "${YACAS_PREFIX}/lib/libyacas.a")
endif ()
  
add_executable (yacas_kernel src/main.cpp src/yacas_kernel.cpp src/yacas_engine.cpp src/hmac_sha256.cpp)
target_link_libraries (yacas_kernel libyacas ${ZMQPP_LIBRARY} ${ZEROMQ_LIBRARY} ${JSONCPP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES} pthread)

install (TARGETS yacas_kernel RUNTIME DESTINATION bin)

set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_IGNORE_FILES "/build/;/.git/;/install/;/nbproject/;~$;${CPACK_SOURCE_IGNORE_FILES}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "yacas_kernel_${YACAS_KERNEL_VERSION}")

set (CPACK_PACKAGE_NAME "yacas_kernel")
set (CPACK_PACKAGE_VENDOR "Yacas Team")
set (CPACK_PACKAGE_CONTACT "yacas@googlegroups.com")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Native yacas kernel for Jupyter.")
set (CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.rst")
set (CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

set (CPACK_GENERATOR DEB)
execute_process (COMMAND dpkg --print-architecture OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE)
string (REGEX REPLACE "(\r?\n)+$" "" CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
set (CPACK_PACKAGE_FILE_NAME "yacas_kernel_${YACAS_KERNEL_VERSION}-1_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
set (CPACK_DEBIAN_PACKAGE_DESCRIPTION "Native yacas kernel for Jupyter, an interactive data science and scientific
 computing environment. Yacas is an easy to use, general purpose Computer
 Algebra System, a program for symbolic manipulation of mathematical 
 expressions. yacas_kernel allows one for performing symbolic calculations
 in interactive computing environment of Jupyter notebook.")
set (CPACK_DEBIAN_PACKAGE_SECTION "math")
set (CPACK_DEBIAN_PACKAGE_RECOMMENDS "yagy")
set (CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst;")

include (CPack)
