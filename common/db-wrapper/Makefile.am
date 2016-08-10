AM_CFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/lib \
	-Wall @GLIB2_CFLAGS@ @MSVC_CFLAGS@ @MYSQL_CFLAGS@ @PGSQL_CFLAGS@

noinst_LTLIBRARIES = libdbwrapper.la

noinst_HEADERS = db-wrapper.h mysql-db-ops.h sqlite-db-ops.h pgsql-db-ops.h

libdbwrapper_la_SOURCES = db-wrapper.c mysql-db-ops.c sqlite-db-ops.c pgsql-db-ops.c

libdbwrapper_la_LDFLAGS = -Wl,-z -Wl,defs
libdbwrapper_la_LIBADD = @SSL_LIBS@ @GLIB2_LIBS@ @MYSQL_LIBS@ -lsqlite3 @PGSQL_LIBS@
