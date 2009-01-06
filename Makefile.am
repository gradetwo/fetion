EXTRA_DIST = \
		Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

FETIONSOURCES = \
	fetion.c \
	fetion.h \
	f_buddy.c  \
	f_buddy.h  \
	f_chat.c  \
	f_chat.h  \
	f_gchat.c \
	f_gchat.h \
	f_zone.c \
	f_zone.h \
	f_group.c  \
	f_group.h  \
	f_login.c  \
	f_login.h  \
	f_sysmsg.c \
	f_sysmsg.h \
       	f_portrait.c \
       	f_portrait.h \
       	f_user.c  \
       	f_user.h  \
	f_util.c  \
	f_util.h  \
	sipmsg.c \
	sipmsg.h

AM_CFLAGS = $(st) 

libfetion_la_LDFLAGS = -module -avoid-version

if STATIC_MSN

st = -DPURPLE_STATIC_PRPL
noinst_LIBRARIES = libfetion.a
libfetion_a_SOURCES = $(FETIONSOURCES)
libfetion_a_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES   = libfetion.la
libfetion_la_SOURCES = $(FETIONSOURCES)
libfetion_la_LIBADD  = $(GLIB_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
