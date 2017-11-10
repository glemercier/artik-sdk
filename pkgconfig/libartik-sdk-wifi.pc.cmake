prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/wifi
version=1.7

Name: ARTIK SDK Wifi
Description: SDK Wifi Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Requires: libartik-sdk-base
Libs: -L${libdir} -lartik-sdk-wifi
Cflags: -I${includedir}
