SUBDIRS = gc

AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_SERVER \
	-DFULL_FEATURE \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@MSVC_CFLAGS@ \
	@LIBARCHIVE_CFLAGS@ \
	@MYSQL_CFLAGS@ \
	-Wall

bin_PROGRAMS = seaf-server

noinst_HEADERS = web-accesstoken-mgr.h  seafile-session.h \
	repo-mgr.h \
	share-mgr.h \
	passwd-mgr.h \
	quota-mgr.h \
	size-sched.h \
	copy-mgr.h \
	http-server.h \
	upload-file.h \
	access-file.h \
	pack-dir.h \
	fileserver-config.h \
	http-status-codes.h \
	zip-download-mgr.h \
	../common/user-mgr.h \
	../common/group-mgr.h \
	../common/org-mgr.h \
	index-blocks-mgr.h \
	http-tx-mgr.h \
	notif-mgr.h

seaf_server_SOURCES = \
	seaf-server.c \
	web-accesstoken-mgr.c  seafile-session.c \
	zip-download-mgr.c \
	index-blocks-mgr.c \
	share-mgr.c \
	passwd-mgr.c \
	quota-mgr.c \
	repo-op.c \
	repo-perm.c \
	size-sched.c \
	virtual-repo.c \
	copy-mgr.c \
	http-server.c \
	upload-file.c \
	access-file.c \
	pack-dir.c \
	fileserver-config.c \
	http-tx-mgr.c \
	notif-mgr.c \
	../common/seaf-db.c \
	../common/branch-mgr.c ../common/fs-mgr.c \
	../common/config-mgr.c \
	repo-mgr.c ../common/commit-mgr.c \
	../common/log.c ../common/object-list.c \
	../common/rpc-service.c \
	../common/vc-common.c \
	../common/seaf-utils.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/seafile-crypt.c \
	../common/diff-simple.c \
	../common/mq-mgr.c \
	../common/user-mgr.c \
	../common/group-mgr.c \
	../common/org-mgr.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/merge-new.c \
	../common/block-tx-utils.c

seaf_server_LDADD = $(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 @LIBEVENT_LIBS@ -levhtp \
	$(top_builddir)/common/cdc/libcdc.la \
	@SEARPC_LIBS@ @JANSSON_LIBS@ ${LIB_WS32} @ZLIB_LIBS@ \
	@LIBARCHIVE_LIBS@ @LIB_ICONV@ \
	@LDAP_LIBS@ @MYSQL_LIBS@ -lsqlite3 \
	@CURL_LIBS@ @JWT_LIBS@
