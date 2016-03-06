#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <sys/time.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "vrt.h"
#include "vsa.h"
#include "vrt_obj.h"
#include "cache/cache.h"

#include "vcc_if.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"


#define DEBUG       1


#define LIBVMOD_LUA_VERSION     "0.6"
#define LIBVMOD_LUA_AUTHOR      "Gu Feng <flygoast@126.com>"


#define	LOG_E(...) fprintf(stderr, __VA_ARGS__);
#ifdef DEBUG
# define LOG_T(...) fprintf(stderr, __VA_ARGS__);
#else
# define LOG_T(...) do {} while(0);
#endif


#define VARNISH_CONTEXT_KEY     "__varnish_context_key"
#define VARNISH_XID_KEY         "__varnish_xid_key"


jmp_buf jmpbuffer;

static pthread_once_t   thread_once = PTHREAD_ONCE_INIT;
static pthread_key_t    thread_vm_key;
static pthread_key_t    request_vm_key;
static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;


typedef int (*handler_t)(lua_State *L, const struct vrt_ctx *ctx);

typedef struct {
    char            *name;
    int              len;
    handler_t        handler;
} var_handler_t;

typedef struct {
    lua_State  *L;
} lua_config_t;


static int traceback(lua_State *L);
static int atpanic(lua_State *L);
static void make_thread_key();
static lua_State *new_lua_state(const char *path, const char *cpath);
static lua_State *new_lua_thread(lua_State *BL);
static void free_lua_state(void *L);
static void free_config(lua_config_t *cfg);
static struct vrt_ctx *get_ctx(lua_State *L);
static void set_ctx(lua_State *L, const struct vrt_ctx *ctx);
static unsigned int get_xid(lua_State *L);
static void set_xid(lua_State *L, unsigned int xid);

static int vcl_var_get(lua_State *L, var_handler_t *vh);
static int vcl_forbidden_set(lua_State *L);

static void inject_bereq(lua_State *L);
static void inject_bereq_http(lua_State *L);
static int vcl_bereq_get(lua_State *L);

static void inject_beresp(lua_State *L);
static void inject_beresp_http(lua_State *L);
static void inject_beresp_backend(lua_State *L);
static int vcl_beresp_get(lua_State *L);
static int vcl_beresp_backend_get(lua_State *L);

static void inject_client(lua_State *L);
static int vcl_client_get(lua_State *L);

static void inject_local(lua_State *L);
static int vcl_local_get(lua_State *L);

static void inject_obj(lua_State *L);
static void inject_obj_http(lua_State *L);
static int vcl_obj_get(lua_State *L);

static void inject_remote(lua_State *L);
static int vcl_remote_get(lua_State *L);

static void inject_req(lua_State *L);
static void inject_req_http(lua_State *L);
static int vcl_req_get(lua_State *L);

static void inject_resp(lua_State *L);
static void inject_resp_http(lua_State *L);
static int vcl_resp_get(lua_State *L);

static void inject_server(lua_State *L);
static int vcl_server_get(lua_State *L);

static void inject_varnish(lua_State *L);
static int vcl_varnish_get(lua_State *L);

static int vcl_bereq_between_bytes_timeout(lua_State *L,
    const struct vrt_ctx *ctx);
static int vcl_bereq_connect_timeout(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_first_byte_timeout(lua_State *L,
    const struct vrt_ctx *ctx);
static int vcl_bereq_method(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_proto(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_retries(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_uncacheable(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_url(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_xid(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_bereq_http_get(lua_State *L);

static int vcl_beresp_age(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_do_esi(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_do_gunzip(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_do_gzip(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_do_stream(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_grace(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_keep(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_proto(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_reason(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_status(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_storage_hint(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_ttl(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_uncacheable(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_was_304(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_backend_name(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_backend_ip(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_backend_port(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_beresp_http_get(lua_State *L);

static int vcl_client_ip(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_client_identity(lua_State *L, const struct vrt_ctx *ctx);

static int vcl_local_ip(lua_State *L, const struct vrt_ctx *ctx);

static int vcl_now(lua_State *, const struct vrt_ctx *ctx);

static int vcl_obj_age(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_grace(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_hits(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_keep(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_proto(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_reason(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_status(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_ttl(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_uncacheable(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_obj_http_get(lua_State *L);

static int vcl_remote_ip(lua_State *L, const struct vrt_ctx *ctx);

static int vcl_req_can_gzip(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_esi(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_esi_level(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_hash_always_miss(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_hash_ignore_busy(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_method(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_proto(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_restarts(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_ttl(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_url(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_xid(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_req_http_get(lua_State *L);

static int vcl_resp_is_streaming(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_resp_proto(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_resp_reason(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_resp_status(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_resp_http_get(lua_State *L);

static int vcl_server_hostname(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_server_identity(lua_State *L, const struct vrt_ctx *ctx);
static int vcl_server_ip(lua_State *L, const struct vrt_ctx *ctx);


static var_handler_t  bereq_handlers[] = {
    { "between_bytes_timeout", sizeof("first_byte_timeout"),
      vcl_bereq_between_bytes_timeout },
    { "connect_timeout", sizeof("connect_timeout") - 1,
      vcl_bereq_connect_timeout },
    { "first_byte_timeout", sizeof("first_byte_timeout"),
      vcl_bereq_first_byte_timeout },
    { "method", sizeof("method") - 1, vcl_bereq_method },
    { "proto", sizeof("proto") - 1, vcl_bereq_proto },
    { "retries", sizeof("retries") - 1, vcl_bereq_retries },
    { "uncacheable", sizeof("uncacheable") - 1, vcl_bereq_uncacheable },
    { "url", sizeof("url") - 1, vcl_bereq_url },
    { "xid", sizeof("xid") - 1, vcl_bereq_xid },
    { NULL, 0, NULL }
};

static var_handler_t  beresp_handlers[] = {
    { "age", sizeof("age") - 1, vcl_beresp_age },
    { "do_esi", sizeof("do_esi") - 1, vcl_beresp_do_esi },
    { "do_gunzip", sizeof("do_gunzip") - 1, vcl_beresp_do_gunzip },
    { "do_gzip", sizeof("do_gzip") - 1, vcl_beresp_do_gzip },
    { "do_stream", sizeof("do_stream") - 1, vcl_beresp_do_stream },
    { "grace", sizeof("grace") - 1, vcl_beresp_grace },
    { "keep", sizeof("keep") - 1, vcl_beresp_keep },
    { "proto", sizeof("proto") - 1, vcl_beresp_proto },
    { "reason", sizeof("reason") - 1, vcl_beresp_reason },
    { "status", sizeof("status") - 1, vcl_beresp_status },
    { "storage_hint", sizeof("storage_hint") - 1, vcl_beresp_storage_hint },
    { "ttl", sizeof("ttl") - 1, vcl_beresp_ttl },
    { "uncacheable", sizeof("uncacheable") - 1, vcl_beresp_uncacheable },
    { "was_304", sizeof("was_304") - 1, vcl_beresp_was_304 },
    { NULL, 0, NULL }
};

static var_handler_t beresp_backend_handlers[] = {
    { "name", sizeof("name") - 1, vcl_beresp_backend_name },
    { "ip", sizeof("ip") - 1, vcl_beresp_backend_ip },
    { "port", sizeof("port") - 1, vcl_beresp_backend_port },
    { NULL, 0, NULL }
};

static var_handler_t  client_handlers[] = {
    { "ip", sizeof("ip") - 1, vcl_client_ip },
    { "identity", sizeof("identity") - 1, vcl_client_identity },
    { NULL, 0, NULL}
};

static var_handler_t  local_handlers[] = {
    { "ip", sizeof("ip") - 1, vcl_local_ip },
    { NULL, 0, NULL }
};

static var_handler_t  varnish_handlers[] = {
    { "now", sizeof("now") - 1, vcl_now },
    { NULL, 0, NULL}
};

static var_handler_t  obj_handlers[] = {
    { "age", sizeof("") - 1, vcl_obj_age },
    { "grace", sizeof("grace") - 1, vcl_obj_grace },
    { "hits", sizeof("hits") - 1, vcl_obj_hits },
    { "keep", sizeof("keep") - 1, vcl_obj_keep },
    { "proto", sizeof("proto") - 1, vcl_obj_proto },
    { "reason", sizeof("reason") - 1, vcl_obj_reason },
    { "status", sizeof("status") - 1, vcl_obj_status },
    { "ttl", sizeof("ttl") - 1, vcl_obj_ttl },
    { "uncacheable", sizeof("uncacheable") - 1, vcl_obj_uncacheable },
    { NULL, 0, NULL }
};

static var_handler_t  remote_handlers[] = {
    { "ip", sizeof("ip") - 1, vcl_remote_ip },
    { NULL, 0, NULL }
};

static var_handler_t  req_handlers[] = {
    { "can_gzip", sizeof("can_gzip") - 1, vcl_req_can_gzip },
    { "esi", sizeof("esi") - 1, vcl_req_esi },
    { "esi_level", sizeof("esi_level") - 1, vcl_req_esi_level },
    { "hash_always_miss", sizeof("hash_always_miss") - 1,
      vcl_req_hash_always_miss },
    { "hash_ignore_busy", sizeof("hash_ignore_busy") - 1,
      vcl_req_hash_ignore_busy },
    { "method", sizeof("method") -1, vcl_req_method },
    { "proto", sizeof("proto") - 1, vcl_req_proto },
    { "restarts", sizeof("restarts") - 1, vcl_req_restarts },
    { "ttl", sizeof("ttl") - 1, vcl_req_ttl },
    { "url", sizeof("url") - 1, vcl_req_url },
    { "xid", sizeof("xid") - 1, vcl_req_xid },
    { NULL, 0, NULL }
};

static var_handler_t resp_handlers[] = {
    { "is_streaming", sizeof("is_streaming") - 1, vcl_resp_is_streaming },
    { "proto", sizeof("proto") - 1, vcl_resp_proto },
    { "reason", sizeof("reason") - 1, vcl_resp_reason },
    { "status", sizeof("status") - 1, vcl_resp_status },
};
 
static var_handler_t  server_handlers[] = {
    { "hostname", sizeof("hostname") - 1, vcl_server_hostname },
    { "identity", sizeof("identity") - 1, vcl_server_identity },
    { "ip", sizeof("ip") - 1, vcl_server_ip },
    { NULL, 0, NULL }
};



/************************* Exported functions ***************************/

/* "import lua" */
int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
    LOG_T("VMOD[lua] init_function called\n");

    pthread_once(&thread_once, make_thread_key);
    priv->free = (vmod_priv_free_f *) free_config;

    return 0;
}


/* "lua.init('/path/to/?.lua;', '/cpath/to/?.so;', '/path/to/foo.lua')" */
void
vmod_init(const struct vrt_ctx *ctx, struct vmod_priv *priv,
          const char *path, const char *cpath, const char *luafile)
{
    lua_config_t  *cfg;
    lua_State     *L;
    int            base;

    if (priv->priv != NULL) {
        LOG_E("VMOD[lua] init should only be invoked once\n");
        return;
    }

    LOG_T("VMOD[lua] init called\n");
    L = new_lua_state(path, cpath);
    if (L == NULL) {
        LOG_E("VMOD[lua] init failed: create Lua state failed\n");
        return;
    }

    if (luaL_loadfile(L, luafile) != 0) {
        LOG_E("VMOD[lua] luaL_loadfile(\"%s\") failed, errstr=\"%s\"\n",
              luafile, luaL_checkstring(L, -1));
        lua_close(L);
        return;
    }

    base = lua_gettop(L);
    lua_pushcfunction(L, traceback);
    lua_insert(L, base);

    if (lua_pcall(L, 0, 0, base) != 0) {
        LOG_E("VMOD[lua] lua_pcall(\"%s\") failed, errstr=\"%s\"\n",
              luafile, luaL_checkstring(L, -1));
        lua_close(L);
        return;
    }

    lua_remove(L, base);

    if (lua_gettop(L) != 0) {
        LOG_E("VMOD[lua] lua VM stack not empty, top: %d\n", lua_gettop(L));
        lua_close(L);
        return;
    }

    cfg = malloc(sizeof(lua_config_t));
    if (cfg == NULL) {
        LOG_E("VMOD[lua] init failed: no memory\n");
        return;
    }

    cfg->L = L;
    priv->priv = cfg;
}


/* "lua.call(function)" */
const char *
vmod_call(const struct vrt_ctx *ctx, struct vmod_priv *priv,
    const char *function)
{
    lua_State     *L, *BL;
    const char    *ret = NULL;
    unsigned int   oxid;
    int            base, type;
    size_t         len;

    LOG_T("VMOD[lua] lua.call(\"%s\") %u\n", function, (unsigned int) pthread_self());

    if (ctx == NULL) {
        LOG_E("VMOD[lua] \"call\" can not be called in this VCL\n");
        return NULL;
    }

    if (priv->priv == NULL) {
        LOG_E("VMOD[lua] \"init\" should be called first in vcl_init\n");
        return NULL;
    }

    /* create a Lua state owned only by this thread */
    BL = pthread_getspecific(thread_vm_key);
    if (BL == NULL) {
        pthread_mutex_lock(&mutex);
        BL = new_lua_thread(((lua_config_t *) priv->priv)->L);
        pthread_mutex_unlock(&mutex);
        pthread_setspecific(thread_vm_key, BL);
    }

    L = pthread_getspecific(request_vm_key);
    if (L == NULL) {
        LOG_T("VMOD[lua] spawn a new Lua thread\n");

        /* stack top of BL is new thread */
        L = new_lua_thread(BL);

        set_ctx(L, ctx);
        set_xid(L, VXID(ctx->req->vsl->wid));

        pthread_setspecific(request_vm_key, L);

    } else {
        oxid = get_xid(L);
        if (oxid != VXID(ctx->req->vsl->wid)) {
            LOG_T("VMOD[lua] spawn a new Lua thread to process new request\n");

            if (!lua_isthread(BL, -1)) {
                LOG_E("VMOD[lua] Lua VM crashed, top is not Lua thread\n");
                lua_settop(BL, 0);
                return NULL;
            }

            /* pop the old thread */
            lua_pop(BL, 1);

            /* another request */
            L = new_lua_thread(BL);

            set_ctx(L, ctx);
            set_xid(L, VXID(ctx->req->vsl->wid));
            pthread_setspecific(request_vm_key, L);

#ifdef DEBUG
        } else {
            LOG_T("VMOD[lua] use old Lua thread\n");
#endif
        }
    }

    lua_getglobal(L, function);

    if (!lua_isfunction(L, -1)) {
        LOG_E("VMOD[lua] global function \"%s\" not fould in lua module\n",
              function);
        lua_pop(L, 1);
        return NULL;
    }

    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_setfenv(L, -2);

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

        ret = lua_tolstring(L, 1, &len);
        ret = WS_Copy(ctx->ws, ret, len);
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
vmod_cleanup(const struct vrt_ctx *ctx, struct vmod_priv *priv)
{
    LOG_T("VMOD[lua] cleanup called\n");

    if (ctx != NULL) {
        LOG_E("VMOD[lua] cleanup should called in vcl_fini\n");
        return;
    }

    if (priv->priv) {
        free_config(priv->priv);
    }
}


const char *
vmod_author(const struct vrt_ctx *ctx)
{
	(void) ctx;

    return LIBVMOD_LUA_AUTHOR;
}


const char *
vmod_version(const struct vrt_ctx *ctx)
{
    (void) ctx;
    return LIBVMOD_LUA_VERSION;
}


/********************* utility functions ********************/

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

    s = NULL;
    if (lua_type(L, -1) == LUA_TSTRING) {
        s = lua_tolstring(L, -1, &len);
    }

    if (s == NULL) {
        s = "unknown reason";
        len = sizeof("unknown reason") - 1;
    }

    LOG_E("VMOD[lua] lua atpanic: Lua VM crashed, reason: %*s\n", (int) len, s);

    longjmp(jmpbuffer, 1);

    /* never get here */

    return 1;
}


static void
make_thread_key()
{
    pthread_key_create(&thread_vm_key, free_lua_state);
    pthread_key_create(&request_vm_key, free_lua_state);
}


static lua_State*
new_lua_state(const char *path, const char *cpath)
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


static lua_State *
new_lua_thread(lua_State *BL)
{
    lua_State  *L;
    L = lua_newthread(BL);

    lua_createtable(L, 0, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");

    lua_createtable(L, 0, 1);
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);

    lua_replace(L, LUA_GLOBALSINDEX);
    return L;
}


static void
free_lua_state(void *L)
{
    if (L) {
        lua_close((lua_State *)L);
    }
}


static void
free_config(lua_config_t *cfg)
{
    if (cfg) {
        lua_close(cfg->L);
        free(cfg);
    }
}


static struct vrt_ctx*
get_ctx(lua_State *L)
{
    struct vrt_ctx  *ctx;

    lua_getglobal(L, VARNISH_CONTEXT_KEY);
    ctx = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return ctx;
}


static void
set_ctx(lua_State *L, const struct vrt_ctx *ctx)
{
    lua_pushlightuserdata(L, (void *)ctx);
    lua_setglobal(L, VARNISH_CONTEXT_KEY);
}


static unsigned int
get_xid(lua_State *L)
{
    unsigned int  xid;

    lua_getglobal(L, VARNISH_XID_KEY);
    xid = (unsigned int) lua_tointeger(L, -1);
    lua_pop(L, 1);

    return xid;
}


static void
set_xid(lua_State *L, unsigned int xid)
{
    lua_pushinteger(L, (lua_Integer) xid);
    lua_setglobal(L, VARNISH_XID_KEY);
}


static int
vcl_var_get(lua_State *L, var_handler_t *vh)
{
    struct vrt_ctx  *ctx;
    const char      *p;
    size_t           len;

    ctx = get_ctx(L);
    if (ctx == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad variable name");
    }

    p = lua_tolstring(L, -1, &len);

    for (; vh->name; vh++) {
        if (len == vh->len && !strcmp(p, vh->name)) {
            return vh->handler(L, ctx);
        }
    }

    lua_pushnil(L);
    return 1;
}


static int
vcl_forbidden_set(lua_State *L)
{
    return luaL_error(L, "table is read only");
}


static void
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


static int
vcl_bereq_get(lua_State *L)
{
    return vcl_var_get(L, bereq_handlers);
}


static void
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
vcl_beresp_backend_get(lua_State *L)
{
    return vcl_var_get(L, beresp_backend_handlers);
}


static int
vcl_beresp_get(lua_State *L)
{
    return vcl_var_get(L, beresp_handlers);
}


static void
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
vcl_client_get(lua_State *L)
{
    return vcl_var_get(L, client_handlers);
}


static void
inject_local(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.local.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_local_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "local");
}


static int
vcl_local_get(lua_State *L)
{
    return vcl_var_get(L, local_handlers);
}


static void
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


static int
vcl_obj_get(lua_State *L)
{
    return vcl_var_get(L, obj_handlers);
}


static void
inject_remote(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.remote.* */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_remote_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "remote");
}


static int
vcl_remote_get(lua_State *L)
{
    return vcl_var_get(L, remote_handlers);
}


static void 
inject_req(lua_State *L)
{
    lua_newtable(L);                    /* table varnish.req.* */

    /* table varnish.req.http.* */
    inject_req_http(L);

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_req_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "req");
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


static int
vcl_req_get(lua_State *L)
{
    return vcl_var_get(L, req_handlers);
}


static void 
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
inject_resp_http(lua_State *L)
{
    lua_newtable(L);                    /* varnish.resp.http table */

    lua_createtable(L, 0, 2);           /* metatable */

    lua_pushcfunction(L, vcl_resp_http_get);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, vcl_forbidden_set);
    lua_setfield(L, -2, "__newindex");

    lua_setmetatable(L, -2);            /* tie the metatable to http table */

    lua_setfield(L, -2, "http");
}


static int
vcl_resp_get(lua_State *L)
{
    return vcl_var_get(L, resp_handlers);
}


static void
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
vcl_server_get(lua_State *L)
{
    return vcl_var_get(L, server_handlers);
}


static void
inject_varnish(lua_State *L)
{
    lua_createtable(L, 0, 99);          /* table varnish.* */

    /* table varnish.client.* */
    inject_client(L);

    /* table varnish.server.* */
    inject_server(L);

    /* table varnish.local.* */
    inject_local(L);

    /* table varnish.remote.* */
    inject_remote(L);

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

    /* Add 'varnish' in package.loaded */
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "loaded");
    lua_pushvalue(L, -3);
    lua_setfield(L, -2, "varnish");
    lua_pop(L, 2);

    lua_setglobal(L, "varnish");
}


static int
vcl_varnish_get(lua_State *L)
{
    return vcl_var_get(L, varnish_handlers);
}


/****************** VCL variables handler *******************/

static int
vcl_bereq_between_bytes_timeout(lua_State *L, const struct vrt_ctx *ctx)
{
    double  timeout;

    timeout = VRT_r_bereq_between_bytes_timeout(ctx);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_bereq_connect_timeout(lua_State *L, const struct vrt_ctx *ctx)
{
    double timeout;

    timeout = VRT_r_bereq_connect_timeout(ctx);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_bereq_first_byte_timeout(lua_State *L, const struct vrt_ctx *ctx)
{
    double  timeout;

    timeout = VRT_r_bereq_first_byte_timeout(ctx);
    lua_pushnumber(L, (lua_Number) timeout);
    return 1;
}


static int
vcl_bereq_method(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_bereq_method(ctx);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_proto(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_bereq_proto(ctx);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_retries(lua_State *L, const struct vrt_ctx *ctx)
{
    int  retries;

    retries = VRT_r_bereq_retries(ctx);
    lua_pushinteger(L, (lua_Integer) retries);
    return 1;
}


static int
vcl_bereq_uncacheable(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_bereq_uncacheable(ctx);
    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_bereq_url(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_bereq_url(ctx);

    lua_pushstring(L, p);

    return 1;
}


static int
vcl_bereq_xid(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_bereq_xid(ctx);
    lua_pushstring(L, p);
    return 1;
}


static int
vcl_bereq_http_get(lua_State *L)
{
    struct vrt_ctx  *ctx;
    struct vsb      *sbh;
    struct http     *hp;
    const char      *p;
    const char      *ret;
    size_t           len;

    ctx = get_ctx(L);
    if (ctx == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get backend request header \"%*s\"\n", (int)len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), (int)len, p, 0);
    AZ(VSB_finish(sbh));

    hp = VRT_selecthttp(ctx, HDR_BEREQ);
    if (!http_GetHdr(hp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_beresp_age(lua_State *L, const struct vrt_ctx *ctx)
{
    double  age;
    age = VRT_r_beresp_ttl(ctx);
    lua_pushnumber(L, (lua_Number) age);

    return 1;
}


static int
vcl_beresp_do_esi(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_do_esi(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_do_gunzip(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_do_gunzip(ctx);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_beresp_do_gzip(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_do_gzip(ctx);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_beresp_do_stream(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_do_stream(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_grace(lua_State *L, const struct vrt_ctx *ctx)
{
    double  grace;

    grace = VRT_r_beresp_grace(ctx);
    lua_pushnumber(L, (lua_Number) grace);

    return 1;
}


static int
vcl_beresp_keep(lua_State *L, const struct vrt_ctx *ctx)
{
    double  keep;

    keep = VRT_r_beresp_keep(ctx);
    lua_pushnumber(L, (lua_Number) keep);

    return 1;
}


static int
vcl_beresp_proto(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_beresp_proto(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_reason(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_beresp_reason(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_status(lua_State *L, const struct vrt_ctx *ctx)
{
    int status;

    status = VRT_r_beresp_status(ctx);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_beresp_storage_hint(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_beresp_storage_hint(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_ttl(lua_State *L, const struct vrt_ctx *ctx)
{
    double  ttl;
    ttl = VRT_r_beresp_ttl(ctx);
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_beresp_uncacheable(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_uncacheable(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_was_304(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_beresp_was_304(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_beresp_backend_name(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_beresp_backend_name(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_backend_ip(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP       ip;
    const char  *p;

    ip =  VRT_r_beresp_backend_ip(ctx);
    p = VRT_IP_string(ctx, ip);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_beresp_backend_port(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP  ip;

    ip = VRT_r_beresp_backend_ip(ctx);

    lua_pushinteger(L, VSA_Port(ip));

    return 1;
}


static int
vcl_beresp_http_get(lua_State *L)
{
    struct vrt_ctx  *ctx;
    struct vsb      *sbh;
    struct http     *hp;
    const char      *p;
    const char      *ret;
    size_t           len;

    ctx = get_ctx(L);
    if (ctx == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get backend response header \"%*s\"\n", (int)len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), (int)len, p, 0);
    AZ(VSB_finish(sbh));

    hp = VRT_selecthttp(ctx, HDR_BERESP);
    if (!http_GetHdr(hp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_client_ip(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP       ip;
    const char  *p;

    ip =  VRT_r_client_ip(ctx);
    p = VRT_IP_string(ctx, ip);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_client_identity(lua_State *L, const struct vrt_ctx *ctx)
{
    lua_pushstring(L, VRT_r_client_identity(ctx));
    return 1;
}


static int
vcl_local_ip(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP       ip;
    const char  *p;

    ip =  VRT_r_local_ip(ctx);
    p = VRT_IP_string(ctx, ip);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_now(lua_State *L, const struct vrt_ctx *ctx)
{
    lua_Number  now;

    now = VRT_r_now(ctx);
    lua_pushnumber(L, now);
    return 1;
}


static int
vcl_obj_age(lua_State *L, const struct vrt_ctx *ctx)
{
    double  age;

    age = VRT_r_obj_age(ctx);
    lua_pushnumber(L, (lua_Number) age);

    return 1;
}


static int
vcl_obj_grace(lua_State *L, const struct vrt_ctx *ctx)
{
    double  grace;

    grace = VRT_r_obj_grace(ctx);
    lua_pushnumber(L, (lua_Number) grace);

    return 1;
}


static int
vcl_obj_hits(lua_State *L, const struct vrt_ctx *ctx)
{
    int  hits;

    hits = VRT_r_obj_hits(ctx);
    lua_pushinteger(L, hits);

    return 1;
}


static int
vcl_obj_keep(lua_State *L, const struct vrt_ctx *ctx)
{
    double  keep;

    keep = VRT_r_obj_keep(ctx);
    lua_pushnumber(L, (lua_Number) keep);

    return 1;
}


static int
vcl_obj_proto(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_obj_proto(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_obj_reason(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_obj_reason(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_obj_status(lua_State *L, const struct vrt_ctx *ctx)
{
    int  status;

    status = VRT_r_obj_status(ctx);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_obj_ttl(lua_State *L, const struct vrt_ctx *ctx)
{
    double  ttl;

    ttl = VRT_r_obj_ttl(ctx);
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_obj_uncacheable(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_obj_uncacheable(ctx);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_obj_http_get(lua_State *L)
{
    /* TODO */
    return 1;
}


static int
vcl_remote_ip(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP       ip;
    const char  *p;

    ip =  VRT_r_remote_ip(ctx);
    p = VRT_IP_string(ctx, ip);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_req_can_gzip(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_req_can_gzip(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_esi(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_req_esi(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_esi_level(lua_State *L, const struct vrt_ctx *ctx)
{
    int  esi_level;

    esi_level = VRT_r_req_esi_level(ctx);
    lua_pushinteger(L, esi_level);

    return 1;
}


static int
vcl_req_hash_always_miss(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_req_hash_always_miss(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_hash_ignore_busy(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_req_hash_ignore_busy(ctx);

    lua_pushboolean(L, ret);
    return 1;
}


static int
vcl_req_method(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *method;

    method = VRT_r_req_method(ctx);
    lua_pushstring(L, method);

    return 1;
}


static int
vcl_req_proto(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *proto;

    proto = VRT_r_req_proto(ctx);
    lua_pushstring(L, proto);

    return 1;
}


static int
vcl_req_restarts(lua_State *L, const struct vrt_ctx *ctx)
{
    int  restarts;

    restarts = VRT_r_req_restarts(ctx);
    lua_pushinteger(L, restarts);

    return 1;
}


static int
vcl_req_ttl(lua_State *L, const struct vrt_ctx *ctx)
{
    double  ttl;

    ttl = VRT_r_req_ttl(ctx);
    lua_pushnumber(L, (lua_Number) ttl);

    return 1;
}


static int
vcl_req_url(lua_State *L, const struct vrt_ctx *ctx)
{
    const char   *url;

    url = VRT_r_req_url(ctx);
    lua_pushlstring(L, url, strlen(url));

    return 1;
}


static int
vcl_req_xid(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_req_xid(ctx);
    lua_pushstring(L, p);
    return 1;
}


static int
vcl_req_http_get(lua_State *L)
{
    struct vrt_ctx  *ctx;
    struct vsb      *sbh;
    struct http     *hp;
    const char      *p;
    const char      *ret;
    size_t           len;

    ctx = get_ctx(L);
    if (ctx == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get header \"%*s\"\n", (int)len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), (int)len, p, 0);
    AZ(VSB_finish(sbh));

    hp = VRT_selecthttp(ctx, HDR_REQ);
    if (!http_GetHdr(hp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_resp_is_streaming(lua_State *L, const struct vrt_ctx *ctx)
{
    int  ret;

    ret = VRT_r_resp_is_streaming(ctx);
    lua_pushboolean(L, ret);

    return 1;
}


static int
vcl_resp_proto(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_resp_proto(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_resp_reason(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *p;

    p = VRT_r_resp_reason(ctx);
    lua_pushstring(L, p);

    return 1;
}


static int
vcl_resp_status(lua_State *L, const struct vrt_ctx *ctx)
{
    int  status;

    status = VRT_r_resp_status(ctx);
    lua_pushinteger(L, status);

    return 1;
}


static int
vcl_resp_http_get(lua_State *L)
{
    struct vrt_ctx  *ctx;
    struct vsb      *sbh;
    struct http     *hp;
    const char      *p;
    const char      *ret;
    size_t           len;

    ctx = get_ctx(L);
    if (ctx == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad http header name");
    }

    p = lua_tolstring(L, -1, &len);

    LOG_T("VMOD[lua] get response header \"%*s\"\n", (int) len, p);

    /* contruct header needed by Varnish */

    sbh = VSB_new_auto();
    AN(sbh);

    VSB_printf(sbh, "%c%.*s:%c", (char)(len + 1), (int) len, p, 0);
    AZ(VSB_finish(sbh));

    hp = VRT_selecthttp(ctx, HDR_RESP);
    if (!http_GetHdr(hp, VSB_data(sbh), &ret)) {
        lua_pushnil(L);
    } else {
        lua_pushstring(L, ret);
    }

    VSB_delete(sbh);
    return 1;
}


static int
vcl_server_hostname(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *hostname;

    hostname = VRT_r_server_hostname(ctx);
    lua_pushstring(L, hostname);

    return 1;
}


static int
vcl_server_identity(lua_State *L, const struct vrt_ctx *ctx)
{
    const char  *identity;

    identity = VRT_r_server_identity(ctx);
    lua_pushstring(L, identity);

    return 1;
}


static int
vcl_server_ip(lua_State *L, const struct vrt_ctx *ctx)
{
    VCL_IP       ip;
    const char  *p;

    ip =  VRT_r_remote_ip(ctx);
    p = VRT_IP_string(ctx, ip);
    lua_pushstring(L, p);

    return 1;
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
