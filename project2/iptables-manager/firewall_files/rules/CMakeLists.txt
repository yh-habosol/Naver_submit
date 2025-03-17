# @@@LICENSE
#
# Copyright (c) 2023 LG Electronics, Inc.
#
# Confidential computer software. Valid license from LG required for
# possession, use or copying. Consistent with FAR 12.211 and 12.212,
# Commercial Computer Software, Computer Software Documentation, and
# Technical Data for Commercial Items are licensed to the U.S. Government
# under vendor's standard commercial license.
#
# LICENSE@@@

set(output_dir "${CMAKE_CURRENT_SOURCE_DIR}/output")

if(EXISTS "${output_dir}")
        file(REMOVE_RECURSE "${output_dir}")
endif()


execute_process(COMMAND python3 ./change_rule.py --oem=JLR
                WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        )


if(EXISTS "${output_dir}/error.txt")
        message(FATAL_ERROR "Error: File exists - ${output_dir}/error.txt")
endif()


set(whitelist_static_file "${output_dir}/whitelist_static.in")
set(whitelist_debug_file "${output_dir}/whitelist_debug.in")



file (READ base.in common_base_rule)
file (READ ${whitelist_static_file} common_wl_rule)
file (READ ${whitelist_debug_file} common_debug_rule)

configure_file(layout.in firewall_rule.conf @only)
list (APPEND RULES ${CMAKE_CURRENT_BINARY_DIR}/firewall_rule.conf)

# Configuration File
install (FILES ${RULES}
        DESTINATION /etc/firewall-manager/
        PERMISSIONS OWNER_WRITE OWNER_READ
        COMPONENT configurations
)

