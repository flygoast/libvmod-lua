AM_CPPFLAGS = @VMOD_INCLUDES@ -Wall -Werror

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_lua.la

libvmod_lua_la_LDFLAGS = -module -export-dynamic -avoid-version -shared -llua \
	-Wl,-e,__libvmod_lua_main

libvmod_lua_la_SOURCES = \
	vmod_lua.c

nodist_libvmod_lua_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

vmod_lua.lo: vcc_if.c vcc_if.h

vcc_if.c: vcc_if.h

vcc_if.h: @VMODTOOL@ $(top_srcdir)/src/vmod_lua.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod_lua.vcc

VMOD_TESTS = $(top_srcdir)/src/tests/*.vtc
.PHONY: $(VMOD_TESTS)

$(top_srcdir)/src/tests/*.vtc: libvmod_lua.la
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_lua.vcc \
	$(VMOD_TESTS)

CLEANFILES = \
	$(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_lua.rst \
	$(builddir)/vmod_lua.man.rst
