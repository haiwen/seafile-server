AM_CFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/lib \
	-Wall @GLIB2_CFLAGS@ @MSVC_CFLAGS@ @MYSQL_CFLAGS@ @PGSQL_CFLAGS@

noinst_LTLIBRARIES = libdbwrapper.la

noinst_HEADERS = db-wrapper.h mysql-db-ops.h sqlite-db-ops.h pgsql-db-ops.h

if WITH_MYSQL
  MYSQL_DB_SRC = mysql-db-ops.c
else
  MYSQL_DB_SRC =
endif

if WITH_POSTGRESQL
  PGSQL_DB_SRC = pgsql-db-ops.c
else
  PGSQL_DB_SRC =
endif

libdbwrapper_la_SOURCES = db-wrapper.c sqlite-db-ops.c $(MYSQL_DB_SRC) $(PGSQL_DB_SRC)

libdbwrapper_la_LDFLAGS = -Wl,-z -Wl,defs
libdbwrapper_la_LIBADD = @SSL_LIBS@ @GLIB2_LIBS@ @MYSQL_LIBS@ -lsqlite3 @PGSQL_LIBS@
