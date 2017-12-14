CMAKE_MINIMUM_REQUIRED	( VERSION 2.8 )
PROJECT			( artik-sdk-connectivity C CXX )

FIND_PACKAGE ( CURL )
FIND_PACKAGE (PkgConfig)
PKG_CHECK_MODULES ( LIBWEBSOCKETS REQUIRED libwebsockets )

SET ( LIB_CONNECTIVITY artik-sdk-connectivity CACHE INTERNAL "" FORCE )
SET ( ARTIK_CONNECTIVITY_INCLUDE_DIR ${LIB_INC}/connectivity CACHE INTERNAL "" FORCE )
SET ( ARTIK_CONNECTIVITY_LIBRARIES ${LIB_CONNECTIVITY} CACHE INTERNAL "" FORCE )

SET ( SRC_CONNECTIVITY
					cloud/artik_cloud.c
					http/common_http.c
					http/linux_http.c
					http/artik_http.c
					network/linux_network.c
					network/artik_network.c
					network/linux/netutils/dhcpc.c
					network/linux/netutils/dhcpd.c
					network/linux/netutils/netlib.c
					websocket/linux_websocket.c
					websocket/artik_websocket.c
					cloud/cpp/artik_cloud.cpp
					http/cpp/artik_http.cpp
					network/cpp/artik_network.cpp
					websocket/cpp/artik_websocket.cpp
)

ADD_LIBRARY ( ${LIB_CONNECTIVITY} SHARED ${SRC_CONNECTIVITY} )

TARGET_INCLUDE_DIRECTORIES ( ${LIB_CONNECTIVITY} PUBLIC
							 ${ARTIK_BASE_INCLUDE_DIR}
							 ${ARTIK_CONNECTIVITY_INCLUDE_DIR}
							 ${CURL_INCLUDE_DIRS}
							 ${LIBWEBSOCKETS_INCLUDE_DIRS}
							 ${ARTIK_BASE_INCLUDE_DIR}/cpp
							 ${ARTIK_CONNECTIVITY_INCLUDE_DIR}/cpp
)

INCLUDE_DIRECTORIES ( linux/netutils )

TARGET_LINK_LIBRARIES ( ${LIB_CONNECTIVITY}
						${LIB_BASE}
						curl
						${LIBWEBSOCKETS_LIBRARIES}
)

SET_TARGET_PROPERTIES ( ${LIB_CONNECTIVITY} PROPERTIES VERSION ${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${LIB_VERSION_PATCH} SOVERSION ${LIB_VERSION_MAJOR} OUTPUT_NAME ${LIB_CONNECTIVITY} )

INSTALL ( TARGETS ${LIB_CONNECTIVITY} LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE )
FILE ( GLOB CONNECTIVITY_HEADERS "${LIB_INC}/connectivity/*.h" )
FILE ( GLOB CONNECTIVITY_HEADERS_CPP "${LIB_INC}/connectivity/cpp/*.hh" )
INSTALL ( FILES ${CONNECTIVITY_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/artik/connectivity" )
INSTALL ( FILES ${CONNECTIVITY_HEADERS_CPP} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/artik/connectivity/cpp" )
