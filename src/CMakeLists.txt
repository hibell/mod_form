set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/modules/")

find_package(APXS REQUIRED)

# mod_form
include_directories(mod_form
        ${APXS_INCLUDES}
)

add_library(mod_form SHARED mod_form.c)

target_link_libraries(mod_form
        ${APXS_LIBRARIES}
)

set_target_properties(mod_form PROPERTIES PREFIX "")
set_target_properties(mod_form PROPERTIES SUFFIX ".so")
set_target_properties(mod_form PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${MOD_DIR}")
