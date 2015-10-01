INCLUDES = -I$(VARNISHSRC)/include -I$(VARNISHSRC) -I$(LUA_INC)

vmoddir = $(VMODDIR)
vmod_LTLIBRARIES = libvmod_lua.la

libvmod_lua_la_LDFLAGS = -module -export-dynamic -version-info 1:0:0 -Wl,-rpath,$(LUA_LIB) -Wl,-e,__libvmod_lua_main
libvmod_lua_la_LIBADD = -L$(LUA_LIB) -llua

libvmod_lua_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_lua.c

vcc_if.c vcc_if.h: $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_lua.vcc
	@PYTHON@ $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_lua.vcc

EXTRA_DIST = vmod_lua.vcc

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h
