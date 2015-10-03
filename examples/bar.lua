local mime = require("mime")
local http = require("socket.http")
local redis = require('redis')

function test_mime()
    return mime.b64("flygoast:yyann");
end

function test_socket()
    local response = http.request("http://www.baidu.com")
    local res = string.sub(response, 1, 30)
    return res
end

function test_redis()
    local params = {
        host = '127.0.0.1',
        port = 6379,
    }
    local client = redis.connect(params)
    local value = client:get('foo')
    return value
end
