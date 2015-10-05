============
vmod_lua
============

----------------------
Varnish Lua Module
----------------------

:Author: Gu Feng
:Date: 2015-10-04
:Version: 0.4
:Manual section: 3

SYNOPSIS
========

vcl
---

::

    import lua;
    
    sub vcl_init {
        lua.init("/path/to/?.lua", "/path/to/?.so", "/path/to/lua/foo.lua");
        return ok;
    }

    sub vcl_fini {
        lua.cleanup();
        return ok;
    }
    
    sub vcl_deliver {
        set resp.http.x-FOO = lua.call("foobar");
    }

foo.lua
-------

::

    function foobar()
        local resp = "X-Foo-Header-Is-" .. varnish.req.http["X-Foo"]
        return resp
    end

DESCRIPTION
===========

Varnish lua vmod is a module to let you can execute lua script in VCL.
VCL variables exported as Lua global variables:

- varnish.req.*
- varnish.bereq.*
- varnish.beresp.*
- varnish.obj.*
- varnish.resp.*

For example, you can got user-agent header of request:

::

    ua = varnish.req.http["User-Agent"]

These variables are read only.

STATUS
======

Proof of concept

FUNCTIONS
=========

init
-----

Prototype
        ::

                init(STRING path, STRING cpath, STRING luafile)
Return value
	VOID
Description
	Initialize a lua state struct to be used. Param 'path' and 'cpath' used to specify Lua search paths. Param 'luafile' specified the lua script need to run. It should be called in vcl_init.
Example
        ::

                lua.init("/path/to/?.lua", "/path/to/?.so", "/path/to/foo.lua");


call
----

Prototype
        ::

                call(STRING S)
Return value
	STRING
Description
	Execute the lua function specified by S, and return a string or nil.
Example
        ::

                set resp.http.x-lua = lua.call("foobar");

cleanup
-------

Prototype
        ::

                cleanup()
Return value
	VOID
Description
	Release the resource used by Lua. It should be called in vcl_fini.
Example
        ::

                lua.cleanup();


DEPENDENCIES
============

* liblua-5.1 (http://www.lua.org)

or

* LuaJIT (http://luajit.org)

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Usage::

 export LUA_INC=/path/to/luainc
 export LUA_LIB=/path/to/lualib
 sh ./autogen.sh
 ./configure VARNISHSRC=DIR [VMODDIR=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`

NOTE
====

If you want to load C modules compiled for Lua with require(), you need to
make shure the public symbols (e.g. lua_setmetatable) are exported.

- Link liblua or libluajit to the varnishd binary file

or

- Link liblua or libluajitevery to every C modules 

COPYRIGHT
=========

This document is licensed under the same license as the
libvmod-lua project. See LICENSE for details.

* Copyright (c) 2013-2015 Gu Feng <flygoast@126.com>
