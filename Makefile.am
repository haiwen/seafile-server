MAKE_CLIENT =

if WIN32
  MAKE_CONTROLLER =
else
  MAKE_CONTROLLER = controller
endif

if COMPILE_FUSE
  MAKE_FUSE = fuse
else
  MAKE_FUSE =
endif

MAKE_SERVER = server tools $(MAKE_CONTROLLER) $(MAKE_FUSE)

SUBDIRS = include lib common python $(MAKE_SERVER) doc

DIST_SUBDIRS = include lib common python server tools controller fuse doc

INTLTOOL = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = install-sh $(INTLTOOL) README.markdown scripts LICENSE.txt

ACLOCAL_AMFLAGS = -I m4

dist-hook:
	git log --format='%H' -1 > $(distdir)/latest_commit
