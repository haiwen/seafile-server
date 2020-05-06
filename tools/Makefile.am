
#AM_CPPFLAGS = @GLIB2_CFLAGS@

bin_PROGRAMS = seaf-server-init ccnet-init

seaf_server_init_SOURCES = seaf-server-init.c ../common/seaf-db.c

ccnet_init_SOURCES = ccnet-init.c

seaf_server_init_LDADD = @GLIB2_LIBS@ -lpthread @MYSQL_LIBS@ -lsqlite3

ccnet_init_LDADD = @SSL_LIBS@ @LIB_RESOLV@ @GLIB2_LIBS@

seaf_server_init_CPPFLAGS = @GLIB2_CFLAGS@ @MSVC_CFLAGS@ @MYSQL_CFLAGS@

ccnet_init_CPPFLAGS = @GLIB2_CFLAGS@ @SSL_CFLAGS@

EXTRA_DIST = seafile-admin

bin_SCRIPTS = seafile-admin
