#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <sys/time.h>
#include <pthread.h>

#include "vrt.h"
#include "vrt_obj.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"


#define DEBUG       1


#define	LOG_E(...) fprintf(stderr, __VA_ARGS__);
#ifdef DEBUG
# define LOG_T(...) fprintf(stderr, __VA_ARGS__);
#else
# define LOG_T(...) do {} while(0);
#endif


#define VARNISH_SESSION_KEY     "__varnish_session_key"


jmp_buf jmpbuffer;

static pthread_once_t thread_once = PTHREAD_ONCE_INIT;
static pthread_key_t  thread_key;


static void make_thread_key();
static lua_State *new_lua_state(struct sess *sp, const char *path,
    const char *cpath);
static void free_lua_state(void *L);
static struct sess *get_sess(lua_State *L);
static void set_sess(lua_State *L, struct sess *sp);
static int vcl_now(lua_State *);
static int vcl_client_ip(lua_State *L);
static int vcl_client_port(lua_State *L);
static int vcl_client_identity(lua_State *L);
static int vcl_server_ip(lua_State *L);
static int vcl_server_hostname(lua_State *L);
static int vcl_server_identity(lua_State *L);
static int vcl_server_port(lua_State *L);
static int vcl_req_request(lua_State *L);
static int vcl_req_url(lua_State *L);
static int vcl_req_proto(lua_State *L);


static void inject_sess_api(lua_State *L, struct sess *sp);
static int traceback(lua_State *L);
static int atpanic(lua_State *L);


static void
make_thread_key()
{
    pthread_key_create(&thread_key, free_lua_state);
}


static struct sess*
get_sess(lua_State *L)
{
    struct sess *sp;

    lua_getglobal(L, VARNISH_SESSION_KEY);
    sp = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return sp;
}


static void
set_sess(lua_State *L, struct sess *sp)
{
    lua_pushlightuserdata(L, sp);
    lua_setglobal(L, VARNISH_SESSION_KEY);
}


static int
vcl_now(lua_State *L)
{
    struct sess  *sp;
    lua_Number    now;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    now = VRT_r_now(sp);
    lua_pushnumber(L, now);
    return 1;
}


static int
vcl_client_ip(lua_State *L)
{
    struct sess  *sp;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    lua_pushlstring(L, sp->addr, strlen(sp->addr));
    return 1;
}


static int
vcl_client_port(lua_State *L)
{
    struct sess  *sp;
    int           port;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    port = VTCP_port(sp->sockaddr);
    lua_pushinteger(L, port);

    return 1;
}


static int
vcl_client_identity(lua_State *L)
{
    struct sess  *sp;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (sp->client_identity != NULL) {
        lua_pushlstring(L, sp->client_identity, strlen(sp->client_identity));
    } else {
        lua_pushlstring(L, sp->addr, strlen(sp->addr));
    }

    return 1;
}


static int
vcl_server_ip(lua_State *L)
{
    struct sess  *sp;
    char          addr[VTCP_ADDRBUFSIZE];
    char          port[VTCP_PORTBUFSIZE];
    char         *p;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    VTCP_name(sp->mysockaddr, sp->mysockaddrlen, addr, sizeof(addr),
              port, sizeof(port));

    p = WS_Dup(sp->ws, addr);
    lua_pushlstring(L, p, strlen(p));

    return 1;
}


static int
vcl_server_hostname(lua_State *L)
{
    struct sess  *sp;
    const char   *hostname;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    hostname = VRT_r_server_hostname(sp);
    lua_pushlstring(L, hostname, strlen(hostname));

    return 1;
}


static int
vcl_server_identity(lua_State *L)
{
    struct sess  *sp;
    const char   *identity;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    identity = VRT_r_server_identity(sp);
    lua_pushlstring(L, identity, strlen(identity));

    return 1;
}


static int
vcl_server_port(lua_State *L)
{
    struct sess  *sp;
    int           port;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    port = VRT_r_server_port(sp);
    lua_pushinteger(L, (lua_Integer)port);

    return 1;
}


static int
vcl_req_request(lua_State *L)
{
    struct sess  *sp;
    const char   *request;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    request = VRT_r_req_request(sp);
    lua_pushlstring(L, request, strlen(request));

    return 1;
}


static int
vcl_req_url(lua_State *L)
{
    struct sess  *sp;
    const char   *url;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    url = VRT_r_req_url(sp);
    lua_pushlstring(L, url, strlen(url));

    return 1;
}


static int
vcl_req_proto(lua_State *L)
{
    struct sess  *sp;
    const char   *proto;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    proto = VRT_r_req_proto(sp);
    lua_pushlstring(L, proto, strlen(proto));

    return 1;
}


static lua_State*
new_lua_state(struct sess *sp, const char *path, const char *cpath)
{
    lua_State   *L;
    const char  *old_path;
    const char  *new_path;
    const char  *old_cpath;
    const char  *new_cpath;

    L = luaL_newstate();
    if (L == NULL) {
        LOG_E("VMOD[lua] create new VM failed\n");
        goto failed;
    }

    luaL_openlibs(L);

    lua_getglobal(L, "package");

    if (!lua_istable(L, -1)) {
        LOG_E("VMOD[lua] the \"package\" table does not exist\n");
        goto failed;
    }

    /* set path */

    lua_pushlstring(L, path, strlen(path));
    lua_pushstring(L, ";");

    lua_getfield(L, -3, "path");
    old_path = lua_tostring(L, -1);

    LOG_T("VMOD[lua] old path: %s\n", old_path);

    lua_concat(L, 3);

    new_path = lua_tostring(L, -1);

    LOG_T("VMOD[lua] new path: %s\n", new_path);

    lua_setfield(L, -2, "path");

    /* set cpath */
    lua_pushlstring(L, cpath, strlen(cpath));
    lua_pushstring(L, ";");

    lua_getfield(L, -3, "cpath");
    old_cpath = lua_tostring(L, -1);

    LOG_T("VMOD[lua] old cpath: %s\n", old_cpath);

    lua_concat(L, 3);

    new_cpath = lua_tostring(L, -1);

    LOG_T("VMOD[lua] new cpath: %s\n", new_cpath);

    lua_setfield(L, -2, "cpath");

    lua_pop(L, 1);      /* rmeove the "package" table */

    inject_sess_api(L, sp);
    set_sess(L, sp);

    return L;

failed:

    if (L) {
        lua_close(L);
    }

    return NULL;
}


static void
free_lua_state(void *L)
{
    if (L) {
        lua_close((lua_State *)L);
    }
}


static void
inject_sess_api(lua_State *L, struct sess *sp)
{
    lua_createtable(L, 0, 99);          /* table varnish.* */

    /* set varnish.now variable */

    lua_pushcfunction(L, vcl_now);
    lua_setfield(L, -2, "now");         /* VCL variable 'now' */

    /* set varnish.client table */

    lua_pushliteral(L, "client");
    lua_newtable(L);

    lua_pushcfunction(L, vcl_client_ip);
    lua_setfield(L, -2, "ip");          /* VCL variable 'client.ip' */

    lua_pushcfunction(L, vcl_client_port);
    lua_setfield(L, -2, "port");        /* VCL no this variable */

    lua_pushcfunction(L, vcl_client_identity);
    lua_setfield(L, -2, "identity");    /* VCL variable 'client.identity' */

    lua_rawset(L, -3);

    /* set varnish.server table */

    lua_pushliteral(L, "server");
    lua_newtable(L);

    lua_pushcfunction(L, vcl_server_ip);
    lua_setfield(L, -2, "ip");          /* VCL variable 'server.ip' */

    lua_pushcfunction(L, vcl_server_hostname);
    lua_setfield(L, -2, "hostname");    /* VCL variable 'server.hostname' */

    lua_pushcfunction(L, vcl_server_identity);
    lua_setfield(L, -2, "identity");    /* VCL variable 'server.identity' */

    lua_pushcfunction(L, vcl_server_port);
    lua_setfield(L, -2, "port");        /* VCL variable 'server.port' */

    lua_rawset(L, -3);

    /* set varnish.req table */

    lua_pushliteral(L, "req");
    lua_newtable(L);

    lua_pushcfunction(L, vcl_req_request);
    lua_setfield(L, -2, "request");

    lua_pushcfunction(L, vcl_req_url);
    lua_setfield(L, -2, "url");

    lua_pushcfunction(L, vcl_req_proto);
    lua_setfield(L, -2, "proto");

    lua_rawset(L, -3);

    lua_setglobal(L, "varnish");
}


static int
traceback(lua_State *L)
{
    if (!lua_isstring(L, 1)) {
        return 1;
    }

    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }

    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }

    lua_pushvalue(L, 1);
    lua_pushinteger(L, 2);
    lua_call(L, 2, 1);
    return 1;
}


static int
atpanic(lua_State *L)
{
    const char  *s;
    size_t       len;

    if (lua_type(L, -1) == LUA_TSTRING) {
        s = lua_tolstring(L, -1, &len);
    }

    if (s == NULL) {
        s = "unknown reason";
        len = sizeof("unknown reason") - 1;
    }

    LOG_E("VMOD[lua] lua atpanic: Lua VM crashed, reason: %*s\n", len, s);

    longjmp(jmpbuffer, 1);

    /* never get here */

    return 1;
}


/* "import lua" */
int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
    LOG_T("VMOD[lua] init_function called\n");

    pthread_once(&thread_once, make_thread_key);

    return 0;
}


/* "lua.init('/path/to/?.lua;', '/cpath/to/?.so;')" */
void
vmod_init(struct sess *sp, struct vmod_priv *priv,
          const char *path, const char *cpath)
{
    lua_State *L;

    LOG_T("VMOD[lua] init called\n");

    if (sp == NULL) {
        LOG_E("VMOD[lua] init can not called in this VCL\n");
        return;
    }

    L = pthread_getspecific(thread_key);
    if (L == NULL) {
        L = new_lua_state(sp, path, cpath);
        if (L == NULL) {
            return;
        }

        pthread_setspecific(thread_key, (const void *)L);
    }
}


/* "lua.loadfile('/path/to/foo.lua')" */
void
vmod_loadfile(struct sess *sp, struct vmod_priv *priv, const char *filename)
{
    lua_State  *L;
    int         base;

    LOG_T("VMOD[lua] loadfile called\n");

    if (sp == NULL) {
        LOG_E("VMOD[lua] loadfile can not be called in this VCL\n");
        return;
    }

    L = pthread_getspecific(thread_key);
    if (L == NULL) {
        LOG_E("VMOD[lua] init should called first\n");
        return;
    }

    if (luaL_loadfile(L, filename) != 0) {
        LOG_E("VMOD[lua] luaL_loadfile(\"%s\") failed, errstr=\"%s\"\n",
              filename, luaL_checkstring(L, -1));
        lua_pop(L, 1);
        return;
    }

    base = lua_gettop(L);
    lua_pushcfunction(L, traceback);
    lua_insert(L, base);

    if (lua_pcall(L, 0, 0, base) != 0) {
        LOG_E("VMOD[lua] lua_pcall(\"%s\") failed, errstr=\"%s\"\n",
              filename, luaL_checkstring(L, -1));
        lua_pop(L, 1);
        return;
    }

    lua_remove(L, base);

    if (lua_gettop(L) != 0) {
        LOG_E("VMOD[lua] lua VM stack not empty, top: %d\n", lua_gettop(L));
    }
    return;
}



/* "lua.call(foo)" */
const char *
vmod_call(struct sess *sp, struct vmod_priv *priv, const char *function)
{
    lua_State   *L;
    const char  *ret = NULL;
    int          base;

    LOG_T("VMOD[lua] lua.call(\"%s\")\n", function);

    if (sp == NULL) {
        LOG_E("VMOD[lua] \"call\" can not be called in this VCL\n");
        return NULL;
    }

    L = pthread_getspecific(thread_key);
    if (L == NULL) {
        LOG_E("VMOD[lua] \"init\" and \"loadfile\" should be called first\n");
        return NULL;
    }

    lua_getglobal(L, function);

    if (!lua_isfunction(L, -1)) {
        LOG_E("VMOD[lua] global function \"%s\" not fould in lua module\n",
              function);
        lua_pop(L, 1);
        return NULL;
    }

    lua_atpanic(L, atpanic);

    if (setjmp(jmpbuffer) == 0) {
        base = lua_gettop(L);
        lua_pushcfunction(L, traceback);
        lua_insert(L, base);

        if (lua_pcall(L, 0, 1, base) != 0) {
            LOG_E("VMOD[lua] call function \"%s\" failed, errstr=\"%s\"\n",
                  function, luaL_checkstring(L, -1));
            lua_pop(L, 1);
            return NULL;
        }

        lua_remove(L, base);

        if ((ret = luaL_checkstring(L, 1)) == NULL) {
            LOG_E("VMOD[lua] all function in lua module MUST return string\n");
            lua_pop(L, 1);
            return NULL;
        }

        ret = WS_Dup(sp->wrk->ws, ret);
        if (ret == NULL) {
            LOG_E("VMOD[lua] WS_Dup failed");
            lua_pop(L, 1);
            return NULL;
        }

        lua_pop(L, 1);

    } else {

        LOG_T("VMOD[lua] varnish execution restored\n");
    }

    /* clear Lua stack */
    lua_settop(L, 0);

    return ret;
}


/* "lua.cleanup()" */
void
vmod_cleanup(struct sess *sp, struct vmod_priv *priv)
{
    lua_State *L;

    LOG_T("VMOD[lua] cleanup called\n");

    if (sp == NULL) {
        LOG_E("VMOD[lua] cleanup can not called in this VCL\n");
        return;
    }

    L = pthread_getspecific(thread_key);
    free_lua_state(L);

    pthread_setspecific(thread_key, NULL);
}
