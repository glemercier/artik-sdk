prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/media
version=1.6

Name: ARTIK SDK Media
Description: SDK Media Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Requires: libartik-sdk-base
Libs: -L${libdir} -lartik-sdk-media
Cflags: -I${includedir}
