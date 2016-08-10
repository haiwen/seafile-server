
#AM_CPPFLAGS = @GLIB2_CFLAGS@

bin_PROGRAMS = seaf-server-init

seaf_server_init_SOURCES = seaf-server-init.c ../common/seaf-db.c

seaf_server_init_LDADD = @GLIB2_LIBS@ $(top_builddir)/common/db-wrapper/libdbwrapper.la -lpthread @MYSQL_LIBS@ @PGSQL_LIBS@

seaf_server_init_CPPFLAGS = @GLIB2_CFLAGS@ @MSVC_CFLAGS@

EXTRA_DIST = seafile-admin

bin_SCRIPTS = seafile-admin
