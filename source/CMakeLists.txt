cmake_minimum_required (VERSION 2.8)
project (nfc)

#file(GLOB_RECURSE SOURCE_TMP "*.c" )
#list(APPEND SRC ${SOURCE_TMP})

find_package(PkgConfig)
pkg_check_modules(PC_JSON-C QUIET json-c)

find_path(JSON-C_INCLUDE_DIR json.h
	HINTS ${PC_JSON-C_INCLUDEDIR} ${PC_JSON-C_INCLUDE_DIRS} PATH_SUFFIXES json-c json)

find_library(JSON-C_LIBRARY NAMES json-c libjson-c
	HINTS ${PC_JSON-C_LIBDIR} ${PC_JSON-C_LIBRARY_DIRS})

include_directories (
	"${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/intfs"
    "${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/types"
	"${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/comps/phpalSli15693/src/Sw"
    "${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/comps/phbalReg/src/RpiSpi"
	"${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/comps/phbalReg/src/R_Pi_spi"
)


set(EXT_LIBS  pthread  m json-c)
set(JSON-C_LIBRARIES ${JSON-C_LIBRARY})
set(JSON-C_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR})
set(CMAKE_C_FLAGS "-std=gnu99")

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(JSON-C DEFAULT_MSG JSON-C_LIBRARY JSON-C_INCLUDE_DIR)
mark_as_advanced(JSON-C_INCLUDE_DIR JSON-C_LIBRARY)

add_definitions(-g -O0 -lwiringPi)

list(APPEND SOURCE "${PROJECT_SOURCE_DIR}/main.c" "${PROJECT_SOURCE_DIR}/nfc.c" "${PROJECT_SOURCE_DIR}/ndef.c" "${PROJECT_SOURCE_DIR}/vital.c")
source_group(src "${PROJECT_SOURCE_DIR}/main.c")

file(GLOB_RECURSE SOURCE_TMP "${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/*.c" )
list(APPEND SOURCE ${SOURCE_TMP})
#source_group(FILES ${SOURCE_TMP})

#list(REMOVE_ITEM SOURCE "${PROJECT_SOURCE_DIR}/NxpRdLib_PublicRelease/ex/NxpRdLib.c")


add_executable(${PROJECT_NAME} ${SOURCE})
target_link_libraries(${PROJECT_NAME} ${EXT_LIBS} wiringPi)
