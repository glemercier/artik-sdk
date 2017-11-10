prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/bluetooth
version=1.7

Name: ARTIK SDK Bluetooth
Description: SDK Bluetooth Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Requires: libartik-sdk-base
Libs: -L${libdir} -lartik-sdk-bluetooth
Cflags: -I${includedir}
