-- -*- Lua -*-
-- This file is a part of the omobus-scgid project.

local M = {} -- public interface

M.options = {
    separator = '&'
}

-- list of known and common scheme ports
-- http://www.iana.org/assignments/uri-schemes.html
M.services = {
    acap     = 674,
    cap      = 1026,
    dict     = 2628,
    ftp      = 21,
    gopher   = 70,
    http     = 80,
    https    = 443,
    iax      = 4569,
    icap     = 1344,
    imap     = 143,
    ipp      = 631,
    ldap     = 389,
    mtqp     = 1038,
    mupdate  = 3905,
    news     = 2009,
    nfs      = 2049,
    nntp     = 119,
    rtsp     = 554,
    sip      = 5060,
    snmp     = 161,
    telnet   = 23,
    tftp     = 69,
    vemmi    = 575,
    afs      = 1483,
    jms      = 5673,
    rsync    = 873,
    prospero = 191,
    videotex = 516
}

local legal = {
    ["-"] = true, ["_"] = true, ["."] = true, ["!"] = true,
    ["~"] = true, ["*"] = true, ["'"] = true, ["("] = true,
    [")"] = true, [":"] = true, ["@"] = true, ["&"] = true,
    ["="] = true, ["+"] = true, ["$"] = true, [","] = true,
    [";"] = true -- can be used for parameters in path
}

local function decode(str)
    local str = str:gsub('+', ' ')
    return (str:gsub("%%(%x%x)", function(c)
	    return string.char(tonumber(c, 16))
	end))
end

local function encode(str)
    return (str:gsub("([^A-Za-z0-9%_%.%-%~])", function(v)
	    return string.upper(string.format("%%%02x", string.byte(v)))
	end))
end

local function encodeValue(str)
    return encode(str)
end

local function encodeSegment(s)
    local legalEncode = function(c)
	    if legal[c] then
		return c
	    end
	    return encode(c)
	end
    return s:gsub('([^a-zA-Z0-9])', legalEncode)
end

function M:build()
	local url = ''
	if self.path then
		local path = self.path
		path:gsub("([^/]+)", function (s) return encodeSegment(s) end)
		url = url .. tostring(path)
	end
	if self.query then
		local qstring = tostring(self.query)
		if qstring ~= "" then
			url = url .. '?' .. qstring
		end
	end
	if self.host then
		local authority = self.host
		if self.port and self.scheme and M.services[self.scheme] ~= self.port then
			authority = authority .. ':' .. self.port
		end
		local userinfo
		if self.user and self.user ~= "" then
			userinfo = self.user
			if self.password then
				userinfo = userinfo .. ':' .. self.password
			end
		end
		if userinfo and userinfo ~= "" then
			authority = userinfo .. '@' .. authority
		end
		if authority then
			if url ~= "" then
				url = '//' .. authority .. '/' .. url:gsub('^/+', '')
			else
				url = '//' .. authority
			end
		end
	end
	if self.scheme then
		url = self.scheme .. ':' .. url
	end
	if self.fragment then
		url = url .. '#' .. self.fragment
	end
	return url
end

function M.buildQuery(tab, sep, key)
	local query = {}
	if not sep then
		sep = M.options.separator or '&'
	end
	local keys = {}
	for k in pairs(tab) do
		keys[#keys+1] = k
	end
	table.sort(keys)
	for _,name in ipairs(keys) do
		local value = tab[name]
		name = encode(tostring(name))
		if key then
			name = string.format('%s[%s]', tostring(key), tostring(name))
		end
		if type(value) == 'table' then
			query[#query+1] = M.buildQuery(value, sep, name)
		else
			local value = encodeValue(tostring(value))
			if value ~= "" then
				query[#query+1] = string.format('%s=%s', name, value)
			else
				query[#query+1] = name
			end
		end
	end
	return table.concat(query, sep)
end

function M.parseQuery(str, sep)
	if not sep then
		sep = M.options.separator or '&'
	end

	local values = {}
	for key,val in str:gmatch(string.format('([^%q=]+)(=*[^%q=]*)', sep, sep)) do
		local key = decode(key)
		local keys = {}
		key = key:gsub('%[([^%]]*)%]', function(v)
				-- extract keys between balanced brackets
				if string.find(v, "^-?%d+$") then
					v = tonumber(v)
				else
					v = decode(v)
				end
				table.insert(keys, v)
				return "="
		end)
		key = key:gsub('=+.*$', "")
		key = key:gsub('%s', "_") -- remove spaces in parameter name
		val = val:gsub('^=+', "")

		if not values[key] then
			values[key] = {}
		end
		if #keys > 0 and type(values[key]) ~= 'table' then
			values[key] = {}
		elseif #keys == 0 and type(values[key]) == 'table' then
			values[key] = decode(val)
		end

		local t = values[key]
		for i,k in ipairs(keys) do
			if type(t) ~= 'table' then
				t = {}
			end
			if k == "" then
				k = #t+1
			end
			if not t[k] then
				t[k] = {}
			end
			if i == #keys then
				t[k] = decode(val)
			end
			t = t[k]
		end
	end
	setmetatable(values, { __tostring = M.buildQuery })
	return values
end

function M:setQuery(query)
	local query = query
	if type(query) == 'table' then
		query = M.buildQuery(query)
	end
	self.query = M.parseQuery(query)
	return query
end

function M:setAuthority(authority)
	self.authority = authority
	self.port = nil
	self.host = nil
	self.userinfo = nil
	self.user = nil
	self.password = nil

	authority = authority:gsub('^([^@]*)@', function(v)
		self.userinfo = v
		return ''
	end)
	authority = authority:gsub("^%[[^%]]+%]", function(v)
		-- ipv6
		self.host = v
		return ''
	end)
	authority = authority:gsub(':([^:]*)$', function(v)
		self.port = tonumber(v)
		return ''
	end)
	if authority ~= '' and not self.host then
		self.host = authority:lower()
	end
	if self.userinfo then
		local userinfo = self.userinfo
		userinfo = userinfo:gsub(':([^:]*)$', function(v)
				self.password = v
				return ''
		end)
		self.user = userinfo
	end
	return authority
end

function M.parse(url)
	local comp = {}
	M.setAuthority(comp, "")
	M.setQuery(comp, "")

	local url = tostring(url or '')
	url = url:gsub('#(.*)$', function(v)
		comp.fragment = v
		return ''
	end)
	url =url:gsub('^([%w][%w%+%-%.]*)%:', function(v)
		comp.scheme = v:lower()
		return ''
	end)
	url = url:gsub('%?(.*)', function(v)
		M.setQuery(comp, v)
		return ''
	end)
	url = url:gsub('^//([^/]*)', function(v)
		M.setAuthority(comp, v)
		return ''
	end)
	comp.path = decode(url)

	setmetatable(comp, {
		__index = M,
		__tostring = M.build}
	)
	return comp
end

function M.removeDotSegments(path)
	local fields = {}
	if string.len(path) == 0 then
		return ""
	end
	local startslash = false
	local endslash = false
	if string.sub(path, 1, 1) == "/" then
		startslash = true
	end
	if (string.len(path) > 1 or startslash == false) and string.sub(path, -1) == "/" then
		endslash = true
	end

	path:gsub('[^/]+', function(c) table.insert(fields, c) end)
	
	local new = {}
	local j = 0
	
	for i,c in ipairs(fields) do
		if c == '..' then
			if j > 0 then
				j = j - 1
			end
		elseif c ~= "." then
			j = j + 1
			new[j] = c
		end
	end
	local ret = ""
	if #new > 0 and j > 0 then
		ret = table.concat(new, '/', 1, j)
	else
		ret = ""
	end
	if startslash then
		ret = '/'..ret
	end
	if endslash then
		ret = ret..'/'
	end
	return ret
end

local function absolutePath(base_path, relative_path)
	if string.sub(relative_path, 1, 1) == "/" then 
		return '/' .. string.gsub(relative_path, '^[%./]+', '')
	end
	local path = base_path
	if relative_path ~= "" then
		path = '/'..path:gsub("[^/]*$", "")
	end
	path = path .. relative_path
	path = path:gsub("([^/]*%./)", function (s)
		if s ~= "./" then return s else return "" end
	end)
	path = string.gsub(path, "/%.$", "/")
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, "([^/]*/%.%./)", function (s)
			if s ~= "../../" then return "" else return s end
		end)
	end
	path = string.gsub(path, "([^/]*/%.%.?)$", function (s)
		if s ~= "../.." then return "" else return s end
	end)
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, '^/?%.%./', '')
	end
	return '/' .. path
end

function M:resolve(other)
	if type(self) == "string" then
		self = M.parse(self)
	end
	if type(other) == "string" then
		other = M.parse(other)
	end
	if other.scheme then 
		return other
	else
		other.scheme = self.scheme
		if not other.authority or other.authority == "" then
			other:setAuthority(self.authority)
			if not other.path or other.path == "" then
				other.path = self.path
				local query = other.query
				if not query or not next(query) then
					other.query = self.query
				end
			else
				other.path = absolutePath(self.path, other.path)
			end
		end
		return other
	end
end

function M:normalize()
    if type(self) == 'string' then
	self = M.parse(self)
    end
    if self.path then
	local path = self.path
	path = absolutePath(path, "")
	-- normalize multiple slashes
	path = string.gsub(path, "//+", "/") 
	self.path = path
    end
    return self
end

return M