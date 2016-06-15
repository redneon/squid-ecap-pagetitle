EXTRA_DIST = \
	adapter_pagetitle.cc

lib_LTLIBRARIES = \
	ecap_adapter_pagetitle.la

noinst_HEADERS = \
	sample.h \
	\
	autoconf.h 

# pagetitle
ecap_adapter_pagetitle_la_SOURCES = adapter_pagetitle.cc
ecap_adapter_pagetitle_la_LDFLAGS = -module -avoid-version $(libecap_LIBS)
ecap_adapter_pagetitle_la_CXXFLAGS = -std=c++11

# -shared -export-dynamic -Wl,-soname,ecap_noop_adapter.so

DISTCLEANFILES = \
        autoconf.h

AM_CPPFLAGS = -I$(top_srcdir)/src $(libecap_CFLAGS)

