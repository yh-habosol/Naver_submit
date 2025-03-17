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

cmake_minimum_required (VERSION 2.8.7)
# cmake_ninimun_required :
# Set the minumun requred version of cmake to build this project using cmake.
# If running cmake version is lower than this version, cmake will stop builing project and report an error.

project (network-firewall)
# project :
# Set the name of the project.
# Can set the default compiler.
# project (network-firewall C) > set C compiler as default CC.
# project (network-firewall NONE) > not need to set compiler. more faster.

find_package(PkgConfig REQUIRED)

add_subdirectory(firewall_files)
