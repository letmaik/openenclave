# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(core)
add_subdirectory(crypto)

if (OE_SGX)
    set(PLATFORM_SRC
        ../common/sgx/qeidentity.c
        ../common/sgx/quote.c
        ../common/sgx/report.c
        ../common/sgx/revocation.c
        ../common/sgx/sgxcertextensions.c
        ../common/sgx/tcbinfo.c
        ../common/sgx/tlsverifier.c
        sgx/link.c
        sgx/qeidinfo.c
        sgx/report.c
        sgx/revocationinfo.c
        sgx/start.S
    )
elseif(OE_TRUSTZONE)
    message("TODO: ADD ARM files.")
endif()

add_library(oeenclave STATIC
    ../common/datetime.c
    asym_keys.c
    random.c
    tls_cert.c
    ${PLATFORM_SRC})

maybe_build_using_clangw(oeenclave)

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

target_link_libraries(oeenclave PUBLIC oecryptombed)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
