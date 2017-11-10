prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/zigbee
version=1.7

Name: ARTIK SDK Zigbee
Description: SDK Zigbee Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Requires: libartik-sdk-base
Libs: -L${libdir} -lartik-sdk-zigbee
Cflags: -I${includedir}
