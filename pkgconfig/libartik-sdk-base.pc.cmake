prefix=/usr
exec_prefix=/usr
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@/artik/base
version=1.6

Name: ARTIK SDK Base
Description: SDK Base Library for Samsung's ARTIK platforms
URL: http://www.artik.io
Version: ${version}
Libs: -L${libdir} -lartik-sdk-base
Cflags: -I${includedir}
