#.rst:
# FindBotan2
# --------
#
# Find Botan2
#
# Find Botan2 headers and libraries.
#
# ::
#
#   BOTAN2_LIBRARIES      - List of libraries when using Botan2.
#   BOTAN2_INCLUDE_DIRS   - List of include directories when using Botan2
#   BOTAN2_FOUND          - True if libbotan2 found.
#   BOTAN2_VERSION        - Version of found libbotan2.

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN2 botan-2)

# handle the QUIETLY and REQUIRED arguments and set BOTAN2_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    BOTAN2
    REQUIRED_VARS BOTAN2_LIBRARIES BOTAN2_INCLUDE_DIRS
    VERSION_VAR BOTAN2_VERSION)