cmake_minimum_required(VERSION 3.25)
project(cryptomoon_version_fixture LANGUAGES NONE)

include("${CRYPTOMOON_GIT_VERSION_MODULE}")
cryptomoon_get_git_commit_short(CRYPTOMOON_GIT_COMMIT_SHORT "${CMAKE_CURRENT_SOURCE_DIR}")
configure_file(version.txt.in version.txt @ONLY)
