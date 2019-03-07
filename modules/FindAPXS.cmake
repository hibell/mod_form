FIND_PROGRAM(APXS apxs)
IF (APXS)
    EXEC_PROGRAM(${APXS}
            ARGS "-q CFLAGS"
            OUTPUT_VARIABLE APXS_C_FLAGS)
    EXEC_PROGRAM(${APXS}
            ARGS "-q EXTRA_CPPFLAGS"
            OUTPUT_VARIABLE APXS_CPP_FLAGS)
    EXEC_PROGRAM(${APXS}
            ARGS "-q INCLUDEDIR"
            OUTPUT_VARIABLE APXS_INCLUDEDIRS)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APXS_C_FLAGS} ${APXS_CPP_FLAGS} -I${APXS_INCLUDEDIRS} -Wl,-undefined -Wl,dynamic_lookup")
    # apxs -q LDFLAGS outputs only a newline which breaks then CMAKE_SHARED_LINKER_FLAGS
    EXEC_PROGRAM(${APXS}
            ARGS "-q EXTRA_LDFLAGS"
            OUTPUT_VARIABLE APXS_LDFLAGS)
    SET(APXS_LIBRARIES
            apr-1
            aprutil-1
    )
    #SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${APXS_LDFLAGS}")
    EXEC_PROGRAM(${APXS}
            ARGS "-q libexecdir"
            OUTPUT_VARIABLE MOD_DIR)
    SET(APACHE_MODULE_DIR "${MOD_DIR}" CACHE PATH
            "Installation directory for Apache modules")
ELSE(APXS)
    MESSAGE(SEND_ERROR "Cannot find apxs anywhere in your path. Please update your path to include the directory containing the script.")
ENDIF(APXS)
