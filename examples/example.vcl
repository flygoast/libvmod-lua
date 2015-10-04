import std;
import lua;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_recv {
    lua.init("/usr/local/varnish/etc/lua/?.lua",
             "/usr/local/varnish/etc/lua/?.so",
             "/usr/local/varnish/etc/varnish/foo.lua");
}

sub vcl_deliver {
    set resp.http.x-md5 = lua.call("test_md5");
    set resp.http.x-json = lua.call("test_json");
    set resp.http.x-mime = lua.call("test_mime");
    set resp.http.x-socket = lua.call("test_socket");
    set resp.http.x-redis = lua.call("test_redis");

    set resp.http.x-now = lua.call("test_now");
    set resp.http.x-server-ip = lua.call("test_server_ip");
    set resp.http.x-server-port = lua.call("test_server_port");
    set resp.http.x-server-identity = lua.call("test_server_identity");
    set resp.http.x-server-hostname = lua.call("test_server_hostname");

    set resp.http.x-obj = lua.call("test_obj");
    set resp.http.x-resp = lua.call("test_resp");

    return (deliver);
}
