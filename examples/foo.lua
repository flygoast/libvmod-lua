local md5 = require("md5")
local cjson = require("cjson")
local mime = require("mime")
local http = require("socket.http")
local redis = require('redis')

function  test_md5()
    return type(md5.sumhexa("abc"))
end

function test_json()
    local t = {}
    t[1] = "hello"
    t[2] = "world"
    return cjson.encode(t)
end


function test_now()
    return varnish.now
end

function test_client_ip()
    return varnish.client.ip
end

function test_client_port()
    return varnish.client.port
end


function test_client_identity()
    return varnish.client.identity
end

function test_server_ip()
    return varnish.server.ip
end

function test_server_port()
    return varnish.server.port
end


function test_server_identity()
    return varnish.server.identity
end

function test_server_hostname()
    return varnish.server.hostname
end


function test_req_url()
    return varnish.req.url
end

function test_req_request()
    return varnish.req.request
end

function test_req_proto()
    return varnish.req.proto
end
function test_req_restarts()
    return varnish.req.restarts
end

function test_req_esi_level()
    return varnish.req.esi_level
end

function test_req_ttl()
    return varnish.req.ttl
end

function test_req_grace()
    return varnish.req.grace
end

function test_req_keep()
    return varnish.req.keep
end

function test_req_xid()
    return varnish.req.xid
end

function test_req_esi()
    if varnish.req.esi then
        return "true"
    else
        return "false"
    end
end

function test_req_can_gzip()
    if varnish.req.can_gzip then
        return "true"
    else
        return "false"
    end
end

function test_req_hash_ignore_busy()
    if varnish.req.hash_ignore_busy then
        return "true"
    else
        return "false"
    end
end

function test_req_hash_always_miss()
    if varnish.req.hash_always_miss then
        return "true"
    else 
        return "false"
    end
end

function test_req_http_host()
    return varnish.req.http.Host
end

function test_req_http_notexisted()
    return varnish.req.http.notexisted
end

function test_backend_name()
    return varnish.req.backend.name
end

function test_backend_healthy()
    if varnish.req.backend.healthy then
        return "true"
    else
        return "false"
    end
end


function test_bereq_request()
    return varnish.bereq.request
end

function test_bereq_url()
    return varnish.bereq.url
end

function test_bereq_proto()
    return varnish.bereq.proto
end

function test_bereq_connect_timeout()
    return varnish.bereq.connect_timeout
end

function test_bereq_first_byte_timeout()
    return varnish.bereq.first_byte_timeout
end

function test_bereq_between_bytes_timeout()
    return varnish.bereq.between_bytes_timeout
end

function test_bereq_http()
    return varnish.bereq.http['user-agent']
end

function test_beresp_status()
    return varnish.beresp.status
end

function test_beresp_response()
    return varnish.beresp.response
end

function test_beresp_ttl()
    return varnish.beresp.ttl
end

function test_beresp_backend()
    return varnish.beresp.backend.name .. ":" .. varnish.beresp.backend.ip .. ":" .. varnish.beresp.backend.port
end

function test_obj()
    return varnish.obj.lastuse .. ":" .. varnish.obj.http["Content-Type"]
end

function test_resp()
    return varnish.resp.status .. ":" .. varnish.resp.http["Server"]
end
