project(n2n C)
cmake_minimum_required(VERSION 3.7)

# N2n information
set(N2N_VERSION 2.3_7.2)
set(N2N_OSNAME ${CMAKE_SYSTEM_NAME})

# Append git revision if available (e.g., 2.3_6.3_r565_976242f)
execute_process(
        COMMAND git rev-list --count HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_REV
        RESULT_VARIABLE GIT_RESULT
        ERROR_QUIET
)
if (GIT_RESULT EQUAL 0)
execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_ID
        ERROR_QUIET
)
string(REGEX REPLACE "\n$" "" GIT_REV "${GIT_REV}")
string(REGEX REPLACE "\n$" "" GIT_ID "${GIT_ID}")
string(STRIP "${GIT_REV}" GIT_REV)
string(STRIP "${GIT_ID}" GIT_ID)
set(N2N_VERSION_FULL "${N2N_VERSION}_r${GIT_REV}_${GIT_ID}")
MESSAGE(STATUS "Build from git rev: ${N2N_VERSION_FULL}")
else()
set(N2N_VERSION_FULL "${N2N_VERSION}")
MESSAGE(STATUS "Git not available, version: ${N2N_VERSION_FULL}")
endif()

include_directories(${PROJECT_SOURCE_DIR} src)

add_definitions(-DN2N_VERSION=\"${N2N_VERSION}\")
add_definitions(-DN2N_VERSION_FULL=\"${N2N_VERSION_FULL}\")
add_definitions(-DN2N_OSNAME=\"${N2N_OSNAME}\")

# AES now uses pure C implementation - always enabled, no OpenSSL needed
add_definitions(-DN2N_HAVE_AES)

# ChaCha20 (B4): pure C implementation, always enabled
add_definitions(-DN2N_HAVE_CC20)

# Crypto library selection
if(USE_GCRYPT)
        add_definitions(-DUSE_GCRYPT=1)
        set(CRYPTO_LIB gcrypt)
elseif(USE_NETTLE)
        add_definitions(-DUSE_NETTLE=1)
        set(CRYPTO_LIB nettle)
elseif(USE_MBEDTLS)
        add_definitions(-DUSE_MBEDTLS=1)
        set(CRYPTO_LIB mbedcrypto)
elseif(USE_OPENSSL)
        add_definitions(-DUSE_OPENSSL=1)
        if(OPENSSL_INCLUDE_DIR)
            include_directories(${OPENSSL_INCLUDE_DIR})
        endif()
        if(OPENSSL_CRYPTO_LIBRARY)
            set(CRYPTO_LIB ${OPENSSL_CRYPTO_LIBRARY})
        else()
            set(CRYPTO_LIB crypto)
        endif()
elseif(USE_ELL)
        add_definitions(-DUSE_ELL=1)
        set(CRYPTO_LIB dl ell)
elseif(WIN32)
        add_definitions(-DUSE_BCRYPT=1)
        set(CRYPTO_LIB bcrypt)
endif()

# Build information
if(NOT DEFINED BUILD_SHARED_LIBS)
set(BUILD_SHARED_LIBS OFF)
endif(NOT DEFINED BUILD_SHARED_LIBS)

if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)

set(CMAKE_INSTALL_DO_STRIP ON)

# Create an n2n object library
add_library(n2n OBJECT
        src/n2n.c
        src/wire.c
        src/version.c
)
set_property(TARGET n2n PROPERTY C_STANDARD 99)
set(OBJECTS $<TARGET_OBJECTS:n2n>)

# Platform-specific configuration
if(DEFINED WIN32)

# Check if WinDivert binaries exist (optional bypass feature)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/win32/WinDivert.dll")
    add_definitions(-DHAVE_WINDIVERT)
    message(STATUS "WinDivert: found, bypass TCP intercept enabled")
else()
    message(STATUS "WinDivert: not found, TCP intercept unavailable")
endif()

set(CMAKE_RC_FLAGS "/nologo /I \"${CMAKE_CURRENT_SOURCE_DIR}/win32\"")
if (MSVC)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4477 /wd4267 /utf-8")
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE)
endif(MSVC)

add_subdirectory(win32)
set(OBJECTS
        ${OBJECTS}
        $<TARGET_OBJECTS:n2n_win32>
        ${CMAKE_CURRENT_SOURCE_DIR}/win32/application.manifest
)
set(EDGE_RESOURCE ${CMAKE_CURRENT_SOURCE_DIR}/win32/edge.rc )
set(SN_RESOURCE ${CMAKE_CURRENT_SOURCE_DIR}/win32/sn.rc )

else(DEFINED WIN32)
set(EDGE_RESOURCE )
set(SN_RESOURCE )
endif(DEFINED WIN32)

# Build n2n static library (enables better dead code elimination when linking)
add_library(n2n_core STATIC
        src/aes.c
        src/sha.c
        src/twofish.c
        src/speck.c
        src/pearson.c
        src/cc20.c
        src/transform_null.c
        src/transform_tf.c
        src/transform_aes.c
        src/transform_cc20.c
        src/transform_speck.c
        src/n2n_keyfile.c
        src/minilzo.c
        src/upnp.c
        src/bypass.c
        src/ikcp.c
        src/ws.c
        src/tuntap_freebsd.c
        src/tuntap_netbsd.c
        src/tuntap_linux.c
        src/tuntap_osx.c
        ${OBJECTS}
)
set_property(TARGET n2n_core PROPERTY C_STANDARD 99)

# Build edge executable
add_executable(edge src/edge.c ${EDGE_RESOURCE})
set_property(TARGET edge PROPERTY C_STANDARD 99)
target_link_libraries(edge n2n_core)

# Build supernode executable
add_executable(supernode src/sn.c ${SN_RESOURCE})
set_property(TARGET supernode PROPERTY C_STANDARD 99)
target_link_libraries(supernode n2n_core)

# Windows-specific configuration
if(DEFINED WIN32)
set_target_properties(edge PROPERTIES LINK_FLAGS "/manifestuac:level='requireAdministrator'")
add_custom_command(
        TARGET supernode
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/win32/install.ps1" "${CMAKE_CURRENT_BINARY_DIR}/install.ps1"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/win32/install.ps1"
)
endif(DEFINED WIN32)

if(WIN32)
  target_link_libraries(n2n_core bcrypt iphlpapi ws2_32)
else()
  # upnp.c uses pthread for async port-map cleanup on shutdown.
  # Don't use find_package(Threads): it fails with cross-compilation
  # toolchains (e.g. OpenWrt mipsel) that don't advertise pthreads to CMake.
  # libdl is required on uClibc toolchains (libpthread depends on it).
  target_link_libraries(n2n_core pthread dl)
endif()

# Dead code elimination
if(NOT WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
    if(APPLE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip")
    else()
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
    endif()
endif()

# Installation
install(TARGETS edge supernode
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

# Documentation generation
if(DEFINED UNIX)
add_dependencies(n2n doc)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/doc)
add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/doc/edge.troff > ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/doc/edge.troff
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/doc/supernode.troff > ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/doc/supernode.troff
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/doc/n2n_v2.troff > ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/doc/n2n_v2.troff
                  )

add_custom_target(doc DEPENDS ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                              ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                              ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                 )

set_source_files_properties(${PROJECT_BINARY_DIR}/doc/edge.8.gz
                            ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                            ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                            PROPERTIES GENERATED 1)

install(FILES ${PROJECT_BINARY_DIR}/doc/edge.8.gz
        DESTINATION /usr/share/man8)
install(FILES ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
        DESTINATION /usr/share/man1)
install(FILES ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
        DESTINATION /usr/share/man7)
endif(DEFINED UNIX)