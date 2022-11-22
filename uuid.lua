-- -*- Lua -*-
-- This file is a part of the omobus-scgid project.

-- Original code created by Rackspace and Thijs Schreijer under Apache License 2.0.

-- Note that this is not a true version 4 (random) UUID (see http://www.ietf.org/rfc/rfc4122.txt).
-- Since `os.time()` precision is only 1 second, it would be hard to guarantee spacial uniqueness 
-- when two hosts generate a uuid after being seeded during the same second. This is solved by 
-- using the node field from a version 1 UUID.  It represents the mac address.

-- **Important:** the random seed is a global piece of data. Hence setting it is
-- an application level responsibility, libraries should never set it!


local M = {}
local math = require('math')
local os = require('os')
local string = require('string')

local bitsize = 32  -- bitsize assumed for Lua VM. See randomseed function below.
local lua_version = tonumber(_VERSION:match("%d%.*%d*"))  -- grab Lua version used

local MATRIX_AND = {{0,0},{0,1} }
local MATRIX_OR = {{0,1},{1,1}}
local HEXES = '0123456789abcdef'

local math_floor = math.floor
local math_random = math.random
local math_abs = math.abs
local string_sub = string.sub
local to_number = tonumber
local assert = assert
local type = type

-- performs the bitwise operation specified by truth matrix on two numbers.
local function BITWISE(x, y, matrix)
  local z = 0
  local pow = 1
  while x > 0 or y > 0 do
    z = z + (matrix[x%2+1][y%2+1] * pow)
    pow = pow * 2
    x = math_floor(x/2)
    y = math_floor(y/2)
  end
  return z
end

local function INT2HEX(x)
  local s,base = '',16
  local d
  while x > 0 do
    d = x % base + 1
    x = math_floor(x/base)
    s = string_sub(HEXES, d, d)..s
  end
  while #s < 2 do s = "0" .. s end
  return s
end

----------------------------------------------------------------------------
-- Creates a new uuid. Either provide a unique hex string, or make sure the
-- random seed is properly set. The module table itself is a shortcut to this
-- function, so `my_uuid = uuid.new()` equals `my_uuid = uuid()`.
-- @return a properly formatted uuid string
-- @param hwaddr (optional) string containing a unique hex value (e.g.: `00:0c:29:69:41:c6`), 
-- to be used to compensate for the lesser `math_random()` function. Use a mac address for solid
-- results. If omitted, a fully randomized uuid will be generated, but then you must ensure that 
-- the random seed is set properly!
-- @usage
-- local uuid = require("uuid")
-- print("here's a new uuid: ",uuid())
function M.new(hwaddr)
  -- bytes are treated as 8bit unsigned bytes.
  local bytes = {
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255),
      math_random(0, 255)
    }

  if hwaddr then
    assert(type(hwaddr)=="string", "Expected hex string, got "..type(hwaddr))
    -- Cleanup provided string, assume mac address, so start from back and cleanup until we've got 12 characters
    local i,str = #hwaddr, hwaddr
    hwaddr = ""
    while i>0 and #hwaddr<12 do
      local c = str:sub(i,i):lower()
      if HEXES:find(c, 1, true) then
        -- valid HEX character, so append it
        hwaddr = c..hwaddr
      end
      i = i - 1
    end
    assert(#hwaddr == 12, "Provided string did not contain at least 12 hex characters, retrieved '"..hwaddr.."' from '"..str.."'")

    -- no split() in lua. :(
    bytes[11] = to_number(hwaddr:sub(1, 2), 16)
    bytes[12] = to_number(hwaddr:sub(3, 4), 16)
    bytes[13] = to_number(hwaddr:sub(5, 6), 16)
    bytes[14] = to_number(hwaddr:sub(7, 8), 16)
    bytes[15] = to_number(hwaddr:sub(9, 10), 16)
    bytes[16] = to_number(hwaddr:sub(11, 12), 16)
  end

  -- set the version
  bytes[7] = BITWISE(bytes[7], 0x0f, MATRIX_AND)
  bytes[7] = BITWISE(bytes[7], 0x40, MATRIX_OR)
  -- set the variant
  bytes[9] = BITWISE(bytes[9], 0x3f, MATRIX_AND)
  bytes[9] = BITWISE(bytes[9], 0x80, MATRIX_OR)
  return INT2HEX(bytes[1])..INT2HEX(bytes[2])..INT2HEX(bytes[3])..INT2HEX(bytes[4]).."-"..
         INT2HEX(bytes[5])..INT2HEX(bytes[6]).."-"..
         INT2HEX(bytes[7])..INT2HEX(bytes[8]).."-"..
         INT2HEX(bytes[9])..INT2HEX(bytes[10]).."-"..
         INT2HEX(bytes[11])..INT2HEX(bytes[12])..INT2HEX(bytes[13])..INT2HEX(bytes[14])..INT2HEX(bytes[15])..INT2HEX(bytes[16])
end

----------------------------------------------------------------------------
-- Improved randomseed function.
-- @param seed the random seed to set (integer from 0 - 2^32, negative values will be made positive)
-- @return the (potentially modified) seed used
-- @usage
-- local uuid = require("uuid")
-- -- see also example at uuid.seed()
-- uuid.randomseed(os.time() + os.getpid())
-- print("here's a new uuid: ",uuid())
function M.randomseed(seed)
    seed = math_floor(math_abs(seed))
    if seed >= (2^bitsize) then
	-- integer overflow, so reduce to prevent a bad seed
	seed = seed - math_floor(seed / 2^bitsize) * (2^bitsize)
    end
    math.randomseed(seed)
    return seed
end

----------------------------------------------------------------------------
-- Seeds the random generator.
-- @usage
-- uuid.seed()
-- print("here's a new uuid: ",uuid())
function M.seed()
    return M.randomseed(os.time() + os.getpid())
end

return setmetatable( M, { __call = function(self, hwaddr) return self.new(hwaddr) end} )
