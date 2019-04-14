-- -*- Lua -*-
-- This file is a part of the omobus-scgid project.

local scgi = {} -- public interface

function scgi.writeHeader(stream, code, params)
    responseTruncate(stream)
    responseWrite(stream, string.format("Status: %d\r\n", code))
    if params ~= nil then
    for key, value in pairs(params) do
        responseWrite(stream, string.format("%s: %s\r\n", key, value))
    end
    end
    responseWrite(stream, "\r\n")
end

function scgi.writeBody(stream, str)
    responseWrite(stream, str)
end

return scgi