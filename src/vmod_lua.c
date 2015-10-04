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


#define LIBVMOD_LUA_VERSION     "0.3"
#define LIBVMOD_LUA_AUTHOR      "Gu Feng <flygoast@126.com>"


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


typedef int (*handler_t)(lua_State *L, struct sess *sp);

typedef struct {
    char            *name;
    int              len;
    handler_t        handler;
} var_handler_t;


static void make_thread_key();
static lua_State *new_lua_state(struct sess *sp, const char *path,
    const char *cpath);
static void free_lua_state(void *L);
static struct sess *get_sess(lua_State *L);
static void set_sess(lua_State *L, struct sess *sp);
static int vcl_now(lua_State *, struct sess *sp);
static int vcl_client_ip(lua_State *L, struct sess *sp);
static int vcl_client_port(lua_State *L, struct sess *sp);
static int vcl_client_identity(lua_State *L, struct sess *sp);
static int vcl_server_ip(lua_State *L, struct sess *sp);
static int vcl_server_hostname(lua_State *L, struct sess *sp);
static int vcl_server_identity(lua_State *L, struct sess *sp);
static int vcl_server_port(lua_State *L, struct sess *sp);
static int vcl_req_request(lua_State *L, struct sess *sp);
static int vcl_req_url(lua_State *L, struct sess *sp);
static int vcl_req_proto(lua_State *L, struct sess *sp);
static int vcl_req_restarts(lua_State *L, struct sess *sp);
static int vcl_req_esi_level(lua_State *L, struct sess *sp);
static int vcl_req_ttl(lua_State *L, struct sess *sp);
static int vcl_req_grace(lua_State *L, struct sess *sp);
static int vcl_req_keep(lua_State *L, struct sess *sp);
static int vcl_req_xid(lua_State *L, struct sess *sp);
static int vcl_req_esi(lua_State *L, struct sess *sp);
static int vcl_req_can_gzip(lua_State *L, struct sess *sp);
static int vcl_req_hash_ignore_busy(lua_State *L, struct sess *sp);
static int vcl_req_hash_always_miss(lua_State *L, struct sess *sp);
static int vcl_req_backend_name(lua_State *L, struct sess *sp);
static int vcl_req_backend_healthy(lua_State *L, struct sess *sp);
static int vcl_req_http_get(lua_State *L);
static int vcl_bereq_request(lua_State *L, struct sess *sp);
static int vcl_bereq_url(lua_State *L, struct sess *sp);
static int vcl_bereq_proto(lua_State *L, struct sess *sp);
static int vcl_bereq_connect_timeout(lua_State *L, struct sess *sp);
static int vcl_bereq_first_byte_timeout(lua_State *L, struct sess *sp);
static int vcl_bereq_between_bytes_timeout(lua_State *L, struct sess *sp);
static int vcl_bereq_http_get(lua_State *L);
static int vcl_beresp_proto(lua_State *L, struct sess *sp);
static int vcl_beresp_status(lua_State *L, struct sess *sp);
static int vcl_beresp_response(lua_State *L, struct sess *sp);
static int vcl_beresp_do_esi(lua_State *L, struct sess *sp);
static int vcl_beresp_do_stream(lua_State *L, struct sess *sp);
static int vcl_beresp_do_gzip(lua_State *L, struct sess *sp);
static int vcl_beresp_do_gunzip(lua_State *L, struct sess *sp);
static int vcl_beresp_ttl(lua_State *L, struct sess *sp);
static int vcl_beresp_grace(lua_State *L, struct sess *sp);
static int vcl_beresp_keep(lua_State *L, struct sess *sp);
static int vcl_beresp_storage(lua_State *L, struct sess *sp);
static int vcl_beresp_backend_name(lua_State *L, struct sess *sp);
static int vcl_beresp_backend_ip(lua_State *L, struct sess *sp);
static int vcl_beresp_backend_port(lua_State *L, struct sess *sp);
static int vcl_beresp_http_get(lua_State *L);
static int vcl_obj_proto(lua_State *L, struct sess *sp);
static int vcl_obj_status(lua_State *L, struct sess *sp);
static int vcl_obj_response(lua_State *L, struct sess *sp);
static int vcl_obj_hits(lua_State *L, struct sess *sp);
static int vcl_obj_ttl(lua_State *L, struct sess *sp);
static int vcl_obj_grace(lua_State *L, struct sess *sp);
static int vcl_obj_keep(lua_State *L, struct sess *sp);
static int vcl_obj_lastuse(lua_State *L, struct sess *sp);
static int vcl_obj_http_get(lua_State *L);
static int vcl_resp_proto(lua_State *L, struct sess *sp);
static int vcl_resp_status(lua_State *L, struct sess *sp);
static int vcl_resp_response(lua_State *L, struct sess *sp);
static int vcl_resp_http_get(lua_State *L);
static int vcl_var_get(lua_State *L, var_handler_t *vh);
static int vcl_forbidden_set(lua_State *L);
static void inject_req_http(lua_State *L);
static void inject_bereq_http(lua_State *L);
static void inject_beresp_http(lua_State *L);
static void inject_obj_http(lua_State *L);
static void inject_resp_http(lua_State *L);
static void inject_varnish(lua_State *L);
static int traceback(lua_State *L);
static int atpanic(lua_State *L);


static var_handler_t  varnish_handlers[] = {
    { "now", sizeof("now") - 1, vcl_now },
    { NULL, 0, NULL}
};

static var_handler_t  client_handlers[] = {
    { "ip", sizeof("ip") - 1, vcl_client_ip },
    { "port", sizeof("port") - 1, vcl_client_port },
    { "identity", sizeof("identity") - 1, vcl_client_identity },
    { NULL, 0, NULL}
};

static var_handler_t  server_handlers[] = {
    { "ip", sizeof("ip") - 1, vcl_server_ip },
    { "port", sizeof("port") - 1, vcl_server_port },
    { "identity", sizeof("identity") - 1, vcl_server_identity },
    { "hostname", sizeof("hostname") - 1, vcl_server_hostname },
    { NULL, 0, NULL }
};

static var_handler_t  req_handlers[] = {
    { "url", sizeof("url") - 1, vcl_req_url },
    { "request", sizeof("request") -1, vcl_req_request },
    { "proto", sizeof("proto") - 1, vcl_req_proto },
    { "restarts", sizeof("restarts") - 1, vcl_req_restarts },
    { "esi_level", sizeof("esi_level") - 1, vcl_req_esi_level },
    { "ttl", sizeof("ttl") - 1, vcl_req_ttl },
    { "grace", sizeof("grace") - 1, vcl_req_grace },
    { "keep", sizeof("keep") - 1, vcl_req_keep },
    { "xid", sizeof("xid") - 1, vcl_req_xid },
    { "esi", sizeof("esi") - 1, vcl_req_esi },
    { "can_gzip", sizeof("can_gzip") - 1, vcl_req_can_gzip },
    { "hash_ignore_busy", sizeof("hash_ignore_busy") - 1,
      vcl_req_hash_ignore_busy },
    { "hash_always_miss", sizeof("hash_always_miss") - 1,
      vcl_req_hash_always_miss },
    { NULL, 0, NULL }
};

static var_handler_t  bereq_handlers[] = {
    { "request", sizeof("request") - 1, vcl_bereq_request },
    { "url", sizeof("url") - 1, vcl_bereq_url },
    { "proto", sizeof("proto") - 1, vcl_bereq_proto },
    { "connect_timeout", sizeof("connect_timeout") - 1,
      vcl_bereq_connect_timeout },
    { "first_byte_timeout", sizeof("first_byte_timeout"),
      vcl_bereq_first_byte_timeout },
    { "between_bytes_timeout", sizeof("first_byte_timeout"),
      vcl_bereq_between_bytes_timeout },
    { NULL, 0, NULL }
};

static var_handler_t  beresp_handlers[] = {
    { "proto", sizeof("proto") - 1, vcl_beresp_proto },
    { "status", sizeof("status") - 1, vcl_beresp_status },
    { "response", sizeof("response") - 1, vcl_beresp_response },
    { "do_esi", sizeof("do_esi") - 1, vcl_beresp_do_esi },
    { "do_stream", sizeof("do_stream") - 1, vcl_beresp_do_stream },
    { "do_gzip", sizeof("do_gzip") - 1, vcl_beresp_do_gzip },
    { "do_gunzip", sizeof("do_gunzip") - 1, vcl_beresp_do_gunzip },
    { "ttl", sizeof("ttl") - 1, vcl_beresp_ttl },
    { "grace", sizeof("grace") - 1, vcl_beresp_grace },
    { "keep", sizeof("keep") - 1, vcl_beresp_keep },
    { "storage", sizeof("storage") - 1, vcl_beresp_storage },
    { NULL, 0, NULL }
};

static var_handler_t  obj_handlers[] = {
    { "proto", sizeof("proto") - 1, vcl_obj_proto },
    { "status", sizeof("status") - 1, vcl_obj_status },
    { "response", sizeof("response") - 1, vcl_obj_response },
    { "hits", sizeof("hits") - 1, vcl_obj_hits },
    { "ttl", sizeof("ttl") - 1, vcl_obj_ttl },
    { "grace", sizeof("grace") - 1, vcl_obj_grace },
    { "keep", sizeof("keep") - 1, vcl_obj_keep },
    { "lastuse", sizeof("lastuse") - 1, vcl_obj_lastuse },
    { NULL, 0, NULL }
};

static var_handler_t resp_handlers[] = {
    { "proto", sizeof("proto") - 1, vcl_resp_proto },
    { "status", sizeof("status") - 1, vcl_resp_status },
    { "response", sizeof("response") - 1, vcl_resp_response },
};
 
static var_handler_t  backend_handlers[] = {
    { "name", sizeof("name") - 1, vcl_req_backend_name },
    { "healthy", sizeof("healthy") - 1, vcl_req_backend_healthy },
    { NULL, 0, NULL }
};

static var_handler_t beresp_backend_handlers[] = {
    { "name", sizeof("name") - 1, vcl_beresp_backend_name },
    { "ip", sizeof("ip") - 1, vcl_beresp_backend_ip },
    { "port", sizeof("port") - 1, vcl_beresp_backend_port },
    { NULL, 0, NULL }
};


static int
vcl_obj_proto(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_obj_proto(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_resp_proto(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_resp_proto(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_resp_status(lua_State *L, struct sess *sp)
{
    int  status;

    status = VRT_r_resp_status(sp);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_resp_response(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_resp_response(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_obj_status(lua_State *L, struct sess *sp)
{
    int  status;

    status = VRT_r_obj_status(sp);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_obj_response(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_obj_response(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_obj_hits(lua_State *L, struct sess *sp)
{
    int  hits;

    hits = VRT_r_obj_hits(sp);
    lua_pushinteger(L, hits);

    return 1;

}


static int
vcl_obj_ttl(lua_State *L, struct sess *sp)
{
    double  ttl;

    ttl = VRT_r_obj_ttl(sp);
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_obj_grace(lua_State *L, struct sess *sp)
{
    double  grace;

    grace = VRT_r_obj_grace(sp);
    lua_pushnumber(L, (lua_Number) grace);

    return 1;
}


static int
vcl_obj_keep(lua_State *L, struct sess *sp)
{
    double  keep;

    keep = VRT_r_obj_keep(sp);
    lua_pushnumber(L, (lua_Number) keep);

    return 1;
}


static int
vcl_obj_lastuse(lua_State *L, struct sess *sp)
{
    double  lastuse;

    lastuse = VRT_r_obj_lastuse(sp);
    lua_pushnumber(L, (lua_Number) lastuse);

    return 1;
}


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
vcl_now(lua_State *L, struct sess *sp)
{
    lua_Number    now;

    now = VRT_r_now(sp);
    lua_pushnumber(L, now);
    return 1;
}


static int
vcl_client_ip(lua_State *L, struct sess *sp)
{
    lua_pushlstring(L, sp->addr, strlen(sp->addr));
    return 1;
}


static int
vcl_client_port(lua_State *L, struct sess *sp)
{
    int  port;

    port = VTCP_port(sp->sockaddr);
    lua_pushinteger(L, port);

    return 1;
}


static int
vcl_client_identity(lua_State *L, struct sess *sp)
{
    if (sp->client_identity != NULL) {
        lua_pushlstring(L, sp->client_identity, strlen(sp->client_identity));
    } else {
        lua_pushlstring(L, sp->addr, strlen(sp->addr));
    }

    return 1;
}


static int
vcl_server_ip(lua_State *L, struct sess *sp)
{
    char   addr[VTCP_ADDRBUFSIZE];
    char   port[VTCP_PORTBUFSIZE];
    char  *p;

    VTCP_name(sp->mysockaddr, sp->mysockaddrlen, addr, sizeof(addr),
              port, sizeof(port));

    p = WS_Dup(sp->ws, addr);
    lua_pushlstring(L, p, strlen(p));

    return 1;
}


static int
vcl_server_hostname(lua_State *L, struct sess *sp)
{
    const char  *hostname;

    hostname = VRT_r_server_hostname(sp);
    lua_pushlstring(L, hostname, strlen(hostname));

    return 1;
}


static int
vcl_server_identity(lua_State *L, struct sess *sp)
{
    const char  *identity;

    identity = VRT_r_server_identity(sp);
    lua_pushlstring(L, identity, strlen(identity));

    return 1;
}


static int
vcl_server_port(lua_State *L, struct sess *sp)
{
    int  port;

    port = VRT_r_server_port(sp);
    lua_pushinteger(L, (lua_Integer)port);

    return 1;
}


static int
vcl_req_request(lua_State *L, struct sess *sp)
{
    const char  *request;

    request = VRT_r_req_request(sp);
    lua_pushlstring(L, request, strlen(request));

    return 1;
}


static int
vcl_req_url(lua_State *L, struct sess *sp)
{
    const char   *url;

    url = VRT_r_req_url(sp);
    lua_pushlstring(L, url, strlen(url));

    return 1;
}


static int
vcl_req_proto(lua_State *L, struct sess *sp)
{
    const char  *proto;

    proto = VRT_r_req_proto(sp);
    lua_pushlstring(L, proto, strlen(proto));

    return 1;
}


static int
vcl_req_restarts(lua_State *L, struct sess *sp)
{
    lua_pushinteger(L, (lua_Integer)sp->restarts);

    return 1;
}


static int
vcl_req_esi_level(lua_State *L, struct sess *sp)
{
    lua_pushinteger(L, (lua_Integer)sp->esi_level);

    return 1;
}


static int
vcl_req_ttl(lua_State *L, struct sess *sp)
{
    double  ttl;

    ttl = EXP_Get_ttl(&(sp->exp));
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_req_grace(lua_State *L, struct sess *sp)
{
    double  grace;

    grace = EXP_Get_grace(&(sp->exp));
    lua_pushnumber(L, (lua_Number) grace);

    return 1;
}


static int
vcl_req_keep(lua_State *L, struct sess *sp)
{
    double  keep;

    keep = EXP_Get_keep(&(sp->exp));
    lua_pushnumber(L, (lua_Number) keep);

    return 1;
}


static int
vcl_req_xid(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_req_xid(sp);
    lua_pushstring(L, p);
    return 1;
}


static int
vcl_req_esi(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_req_esi(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_can_gzip(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_req_can_gzip(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_hash_ignore_busy(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_req_hash_ignore_busy(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_hash_always_miss(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_req_hash_always_miss(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_backend_name(lua_State *L, struct sess *sp)
{
    struct director  *d;
    const char       *p;

    d = VRT_r_req_backend(sp);

    p = VRT_backend_string(sp, d);

    if (!p) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, p);
    }

    return 1;
}


static int
vcl_req_backend_healthy(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_req_backend_healthy(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_bereq_request(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_bereq_request(sp);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_url(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_bereq_url(sp);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_proto(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_bereq_proto(sp);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_connect_timeout(lua_State *L, struct sess *sp)
{
    double timeout;

    timeout = VRT_r_bereq_connect_timeout(sp);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_bereq_first_byte_timeout(lua_State *L, struct sess *sp)
{
    double timeout;

    timeout = VRT_r_bereq_first_byte_timeout(sp);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_bereq_between_bytes_timeout(lua_State *L, struct sess *sp)
{
    double timeout;

    timeout = VRT_r_bereq_between_bytes_timeout(sp);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_beresp_proto(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_beresp_proto(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_status(lua_State *L, struct sess *sp)
{
    int status;

    status = VRT_r_beresp_status(sp);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_beresp_response(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_beresp_response(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_do_esi(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_beresp_do_esi(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_do_stream(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_beresp_do_stream(sp);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_do_gzip(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_beresp_do_gzip(sp);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_beresp_do_gunzip(lua_State *L, struct sess *sp)
{
    int  ret;

    ret = VRT_r_beresp_do_gunzip(sp);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_beresp_ttl(lua_State *L, struct sess *sp)
{
    double  ttl;
    ttl = VRT_r_beresp_ttl(sp);
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_beresp_grace(lua_State *L, struct sess *sp)
{
    double  grace;

    grace = VRT_r_beresp_grace(sp);
    lua_pushnumber(L, (lua_Number) grace);

    return 1;
}


static int
vcl_beresp_keep(lua_State *L, struct sess *sp)
{
    double  keep;

    keep = VRT_r_beresp_keep(sp);
    lua_pushnumber(L, (lua_Number) keep);

    return 1;
}


static int
vcl_beresp_storage(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_beresp_storage(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_backend_name(lua_State *L, struct sess *sp)
{
    const char  *p;

    p = VRT_r_beresp_backend_name(sp);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_backend_ip(lua_State *L, struct sess *sp)
{
    char   addr[VTCP_ADDRBUFSIZE];
    char   port[VTCP_PORTBUFSIZE];
    char  *p;

    VTCP_name(sp->vbc->addr, sp->vbc->addrlen, addr, sizeof(addr),
              port, sizeof(port));

    p = WS_Dup(sp->ws, addr);
    lua_pushlstring(L, p, strlen(p));

    return 1;
}


static int
vcl_beresp_backend_port(lua_State *L, struct sess *sp)
{
    int  port;

    port = VRT_r_beresp_backend_port(sp);
    lua_pushinteger(L, port);

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

    inject_varnish(L);

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


static int
vcl_req_http_get(lua_State *L)
{
    struct sess  *sp;
    struct vsb   *sbh;
    const char   *p;
    char         *ret;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get header \"%*s\"\n", len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), len, p, 0);
    AZ(VSB_finish(sbh));

    if (!http_GetHdr(sp->http, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_bereq_http_get(lua_State *L)
{
    struct sess  *sp;
    struct vsb   *sbh;
    const char   *p;
    char         *ret;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get backend request header \"%*s\"\n", len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), len, p, 0);
    AZ(VSB_finish(sbh));

    if (!http_GetHdr(sp->wrk->bereq, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_beresp_http_get(lua_State *L)
{
    struct sess  *sp;
    struct vsb   *sbh;
    const char   *p;
    char         *ret;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get backend response header \"%*s\"\n", len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), len, p, 0);
    AZ(VSB_finish(sbh));

    if (!http_GetHdr(sp->wrk->beresp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_obj_http_get(lua_State *L)
{
    struct sess  *sp;
    struct vsb   *sbh;
    const char   *p;
    char         *ret;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get obj header \"%*s\"\n", len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), len, p, 0);
    AZ(VSB_finish(sbh));

    if (!http_GetHdr(sp->obj->http, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_resp_http_get(lua_State *L)
{
    struct sess  *sp;
    struct vsb   *sbh;
    const char   *p;
    char         *ret;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get response header \"%*s\"\n", len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), len, p, 0);
    AZ(VSB_finish(sbh));

    if (!http_GetHdr(sp->wrk->resp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_forbidden_set(lua_State *L)
{
    return luaL_error(L, "table is read only");
}


static void
inject_req_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.req.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_req_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static void
inject_bereq_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.bereq.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_bereq_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static void
inject_beresp_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.beresp.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_beresp_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static void
inject_obj_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.obj.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_obj_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static void
inject_resp_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.resp.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_obj_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static int
vcl_varnish_get(lua_State *L)
{
    return vcl_var_get(L, varnish_handlers);
}


static int
vcl_client_get(lua_State *L)
{
    return vcl_var_get(L, client_handlers);
}


static int
vcl_server_get(lua_State *L)
{
    return vcl_var_get(L, server_handlers);
}


static int
vcl_req_get(lua_State *L)
{
    return vcl_var_get(L, req_handlers);
}


static int
vcl_req_backend_get(lua_State *L)
{
    return vcl_var_get(L, backend_handlers);
}

static int
vcl_beresp_backend_get(lua_State *L)
{
    return vcl_var_get(L, beresp_backend_handlers);
}

static int
vcl_bereq_get(lua_State *L)
{
    return vcl_var_get(L, bereq_handlers);
}


static int
vcl_beresp_get(lua_State *L)
{
    return vcl_var_get(L, beresp_handlers);
}


static int
vcl_obj_get(lua_State *L)
{
    return vcl_var_get(L, obj_handlers);
}


static int
vcl_resp_get(lua_State *L)
{
    return vcl_var_get(L, resp_handlers);
}


static int
vcl_var_get(lua_State *L, var_handler_t *vh)
{
    struct sess  *sp;
    const char   *p;
    size_t        len;

    sp = get_sess(L);
    if (sp == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad variable name");
    }

    p = lua_tolstring(L, -1, &len);

    for (; vh->name; vh++) {
        if (len == vh->len && !strcmp(p, vh->name)) {
            return vh->handler(L, sp);
        }
    }

    lua_pushnil(L);
    return 1;
}


static int
inject_client(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.client.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_client_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "client");
}


static int
inject_server(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.server.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_server_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "server");
}


static int
inject_req_backend(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.req.backend.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_req_backend_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "backend");
}


static int
inject_beresp_backend(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.resp.backend.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_beresp_backend_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "backend");
}


static int
inject_req(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.req.* */

    /* table varnish.req.http.* */
    inject_req_http(L);

    /* table varnish.req.backend.* */
    inject_req_backend(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_req_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "req");
}


static int
inject_bereq(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.bereq.* */

    /* table varnish.bereq.http.* */
    inject_bereq_http(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_bereq_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "bereq");
}


static int
inject_beresp(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.beresp.* */

    /* table varnish.beresp.http.* */
    inject_beresp_http(L);

    /* table varnish.beresp.backend.* */
    inject_beresp_backend(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_beresp_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "beresp");
}


static int
inject_obj(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.obj.* */

    /* table varnish.obj.http.* */
    inject_obj_http(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_obj_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "obj");
}


static int
inject_resp(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.resp.* */

    /* table varnish.resp.http.* */
    inject_resp_http(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_resp_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "resp");
}


static void
inject_varnish(lua_State *L)
{
    lua_createtable(L, 0, 99);          /* table varnish.* */

    /* table varnish.client.* */
    inject_client(L);

    /* table varnish.server.* */
    inject_server(L);

    /* table varnish.req.* */
    inject_req(L);

    /* table varnish.bereq.* */
    inject_bereq(L);

    /* table varnish.beresp.* */
    inject_beresp(L);

    /* table varnish.obj.* */
    inject_obj(L);

    /* table varnish.resp.* */
    inject_resp(L);

    lua_createtable(L, 0, 2);           /* metatable */
    lua_pushcfunction(L, vcl_varnish_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

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


/* "lua.init('/path/to/?.lua;', '/cpath/to/?.so;', '/path/to/foo.lua')" */
void
vmod_init(struct sess *sp, struct vmod_priv *priv,
          const char *path, const char *cpath, const char *luafile)
{
    lua_State  *L;
    int         base;

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

        if (luaL_loadfile(L, luafile) != 0) {
            LOG_E("VMOD[lua] luaL_loadfile(\"%s\") failed, errstr=\"%s\"\n",
                  luafile, luaL_checkstring(L, -1));
            lua_pop(L, 1);
            return;
        }

        base = lua_gettop(L);
        lua_pushcfunction(L, traceback);
        lua_insert(L, base);
    
        if (lua_pcall(L, 0, 0, base) != 0) {
            LOG_E("VMOD[lua] lua_pcall(\"%s\") failed, errstr=\"%s\"\n",
                  luafile, luaL_checkstring(L, -1));
            lua_settop(L, 0);
            return;
        }
    
        lua_remove(L, base);
    
        if (lua_gettop(L) != 0) {
            LOG_E("VMOD[lua] lua VM stack not empty, top: %d\n", lua_gettop(L));
        }

        pthread_setspecific(thread_key, (const void *)L);
    }
}


/* "lua.call(foo)" */
const char *
vmod_call(struct sess *sp, struct vmod_priv *priv, const char *function)
{
    lua_State    *L;
    const char   *ret = NULL;
    struct sess  *osp;
    int           base, type;

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

    osp = get_sess(L);
    if (osp != sp) {
        /* set new sess to global variable */
        set_sess(L, sp);
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
            /* clear Lua stack to execute other functions */
            lua_settop(L, 0);
            return NULL;
        }

        lua_remove(L, base);

        type = lua_type(L, 1);
        switch (type) {
        case LUA_TNIL:
            LOG_T("VMOD[lua] function \"%s\" returned nil\n",
                  function);
            lua_pop(L, 1);
            return NULL;
        case LUA_TSTRING:
        case LUA_TNUMBER:
            break;
        default:
            LOG_E("VMOD[lua] function \"%s\" returned type \"%s\""
                  ", should return string or nil\n",
                  function, lua_typename(L, type));
            lua_pop(L, 1);
            return NULL;
        }

        ret = lua_tostring(L, 1);
        ret = WS_Dup(sp->wrk->ws, ret);
        if (ret == NULL) {
            LOG_E("VMOD[lua] WS_Dup failed\n");
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


const char *
vmod_author(struct sess *sp)
{
	(void) sp;

    return LIBVMOD_LUA_AUTHOR;
}


const char *
vmod_version(struct sess *sp)
{
    (void) sp;
    return LIBVMOD_LUA_VERSION;
}


#if __WORDSIZE == 64
#define RUNTIME_LINKER "/lib64/ld-linux-x86-64.so.2"
#else
#define RUNTIME_LINKER "/lib/ld-linux.so.2"
#endif


#ifndef __SO_INTERP__
#define __SO_INTERP__
const char __invoke_dynamic_linker__[] __attribute__ ((section (".interp")))
    = RUNTIME_LINKER;
#endif


void
__libvmod_lua_main(void)
{
    printf("** Varnish Lua Module **\n");
    printf("Author: " LIBVMOD_LUA_AUTHOR "\n");
    printf("Version: " LIBVMOD_LUA_VERSION "\n");
    printf("Repository: https://github.com/flygoast/libvmod-lua\n");
    exit(0);
}
