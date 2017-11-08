prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/mqtt
version=1.6

Name: ARTIK SDK MQTT
Description: SDK MQTT Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Requires: libartik-sdk-base
Libs: -L${libdir} -lartik-sdk-mqtt
Cflags: -I${includedir}
