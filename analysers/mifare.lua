-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id mifare
-- @title MIFARE Classic
-- @description Inspect MIFARE Classic sectors with default keys
-- @version 1.0.0
--
-- This file is part of Cardpeek, the smartcard reader utility.
--
-- Copyright 2009-2013 by 'L1L1'
--
-- Cardpeek is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- Cardpeek is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with Cardpeek.  If not, see <http://www.gnu.org/licenses/>.
--


local cp = require('cardpeek')
local util = require('lib.util')
local function band(a,b) return a & b end
local function bxor(a,b) return a ~ b end
local function rshift(a,b) return a >> b end
local function convert(data,width) return data:convert(width) end
local function last_atr() local atr,failure=cp.card.atr(); assert(not failure,failure and failure.message); return atr.bytes end
local apdu = require('lib.apdu')

MIFARE_STD_KEYS= {
    ["default"] = {
        { 'a', "FFFFFFFFFFFF" },
        { 'a', "A0A1A2A3A4A5" },
        { 'b', "B0B1B2B3B4B5" },
        { 'b', "FFFFFFFFFFFF" },
        { 'a', "000000000000" },
        { 'b', "000000000000" }
    }
}

function mifare_read_uid()
	return util.transmit(util.bytes(8,"FF CA 00 00 00"))
end

local USE_VOLATILE_MEM = true

function mifare_load_key(keynum,keyval,options)
    local command, response

    local key = util.bytes(8,keyval)

    if options==nil then 
        if USE_VOLATILE_MEM then
            -- first try volatile memory
            response = mifare_load_key(keynum,keyval,0x00)
            if response.status==0x6986 then
                USE_VOLATILE_MEM = false
                return mifare_load_key(keynum,keyval,0x20)
            else 
                return response
            end
        else
            -- volatile memory not available
            return mifare_load_key(keynum,keyval,0x20) 
        end
    end

    command = util.bytes(8,"FF 82", options, keynum, #key, key)

    response = util.transmit(command)

    return response
end

function mifare_authenticate(addr,keynum,keytype)
	return util.transmit(util.bytes(8,"FF 86 00 00 05 01",rshift(addr,8),band(addr,0xFF),keytype,keynum))
end

function mifare_read_binary(addr,len)
	return util.transmit(util.bytes(8,"FF B0",rshift(addr,8),band(addr,0xFF),len))
end

function mifare_textify(node,data)
	local i
	local r = data:to_hex() .. " ("

	for i=0,#data-1 do
		if data[i+1]>=32 and data[i+1]<127 then
			r = r .. string.char(data[i+1])
		else
			r = r .. "."
		end	
	end
    r = r .. ")"
	node:set("alternative",r)
end

function mifare_trailer(node,data)
    local keyA = util.sub(data,0,5)
    local perm = util.sub(data,6,9)
    local keyB = util.sub(data,10,15)

    r = "KeyA:(redacted) Access:" .. perm:to_hex() .. " keyB:(redacted)" 
    node:set("alternative",r)
end

MIFARE_ACC_KEY = { "--", "A-", "-B", "AB" } 

MIFARE_ACC_DATA = { -- C1 C2 C3
  { 3, 3, 3, 3 }, -- 000
  { 3, 0, 0, 3 }, -- 001
  { 3, 0, 0, 0 }, -- 010
  { 2, 2, 0, 0 }, -- 011
  { 3, 2, 0, 0 }, -- 100
  { 2, 0, 0, 0 }, -- 101
  { 3, 2, 2, 3 }, -- 110
  { 0, 0, 0, 0 } -- 111
}

MIFARE_ACC_TAILER = {
  { 0, 1, 1, 0, 1, 1 }, -- 000
  { 0, 1, 1, 1, 1, 1 }, -- 001
  { 0, 0, 1, 0, 1, 0 }, -- 010 
  { 0, 2, 3, 2, 0, 2 }, -- 011
  { 0, 2, 3, 0, 0, 2 }, -- 100
  { 0, 0, 3, 2, 0, 0 }, -- 101
  { 0, 0, 3, 0, 0, 2 }, -- 110
  { 0, 0, 3, 0, 0, 0 } -- 111
}

function mifare_data_access(node, block, code)
    local access_string = ""

    access_string = access_string .. "read:" .. MIFARE_ACC_KEY[MIFARE_ACC_DATA[code+1][1]+1] .. " "
    access_string = access_string .. "write:" .. MIFARE_ACC_KEY[MIFARE_ACC_DATA[code+1][2]+1] .. " "
    access_string = access_string .. "inc:" .. MIFARE_ACC_KEY[MIFARE_ACC_DATA[code+1][3]+1] .. " "
    access_string = access_string .. "dec:" .. MIFARE_ACC_KEY[MIFARE_ACC_DATA[code+1][4]+1]
    
    util.node(node, "item", string.format("block %i", block), tostring(code), access_string)
end

function mifare_key_access(node, code)
    local access_string = ""

    subnode = util.node(node, "item", "block 3", tostring(code), "")

    access_string = "read:-- write:" .. MIFARE_ACC_KEY[MIFARE_ACC_TAILER[code+1][2]+1] 

    util.node(subnode, "item", "key A", nil, access_string) 

    access_string = "read:" .. MIFARE_ACC_KEY[MIFARE_ACC_TAILER[code+1][3]+1] .. " "
                 .. "write:" .. MIFARE_ACC_KEY[MIFARE_ACC_TAILER[code+1][4]+1]
 
    util.node(subnode, 'item', 'Access bits', nil, access_string)

    access_string = "read:" .. MIFARE_ACC_KEY[MIFARE_ACC_TAILER[code+1][5]+1] .. " "
                 .. "write:" .. MIFARE_ACC_KEY[MIFARE_ACC_TAILER[code+1][6]+1] 

    util.node(subnode, 'item', 'Key B', nil, access_string)
end

function mifare_access_permission_get(tailer, block)
    local access_bits = util.sub(tailer,6,9):convert(1)
    local access
    local ssecca 

    if block==0 then
        access = access_bits[13]*4 + access_bits[24]*2 + access_bits[21]
        ssecca = access_bits[9]*4 + access_bits[5]*2 + access_bits[17]
    elseif block==1 then
        access = access_bits[11]*4 + access_bits[23]*2 + access_bits[19]
        ssecca = access_bits[7]*4 + access_bits[3]*2 + access_bits[15]
    elseif block==2 then
        access = access_bits[10]*4 + access_bits[22]*2 + access_bits[18]
        ssecca = access_bits[6]*4 + access_bits[2]*2 + access_bits[14]
    else 
        access = access_bits[9]*4 + access_bits[21]*2 + access_bits[17]
        ssecca = access_bits[5]*4 + access_bits[1]*2 + access_bits[13]
    end

    if bxor(ssecca,7)~=access then
        return access, false 
    end
    return access, true
end


-- 
-- mifare_read_card(keys) reads a mifare card using the keys specified in <keys>
-- it returns 3 elements: 
--  * A table representing the content of the readable sectors (or nil)
--  * The card UID (or nil)
--
function mifare_read_card(keys)
    local mfdata = {}
    local sector
    local block
    local response
    local authenticated
    local key, current_key
    local atr = last_atr()
    local auth_status
    local resp
    local sw

    if util.get(atr,13)==0 and util.get(atr,14)==2 then
        mfdata['last_sector'] = 63
    else
        mfdata['last_sector'] = 15
    end

    response = mifare_read_uid()
    local mfuid = response.data
    local sw = response.status
    if sw~=0x9000 then
        cp.log.error("Could not get Mifare UID.")
        return nil, nil
    end

    for sector=0,mfdata['last_sector'] do

        authenticated = false

        keylist = keys[sector] or keys["default"]
	
        if keylist then

            for block = 0,3 do
                if not authenticated then
                    for _, key in ipairs(keylist) do
                        if current_key==nil or key[2]~=current_key[2] or key[1]~=current_key[1] then
                            mifare_load_key(0x0, key[2])
                            current_key = key
                        end
                        if key[1]=='a' then
                            response = mifare_authenticate(sector*4,0x0,0x60)
                            sw = response.status
                        else
                            response = mifare_authenticate(sector*4,0x0,0x61)
                            sw = response.status
                        end
                        if sw==0x9000 then
                            auth_status = "OK"
                            authenticated = true
                        else
                            auth_status = "FAIL"
                            authenticated = false
                        end
                        cp.log.info(string.format("Authenticating sector %2i, block %i, with key type %s: %s",sector,block,key[1],auth_status))
                        if authenticated then
                            break
                        end
                    end
                end--if           

                if authenticated then
                    cp.log.info(string.format("Reading from sector %2i, Block %i:",sector,block))
                    response = mifare_read_binary(sector*4+block,16)
                        sw, resp = response.status, response.data

                    if sw == 0x9000 then
                        if block==3 then
                            mfdata[sector*4+block] = util.concat(util.bytes(8,"000000000000"),util.sub(resp,6,9),util.bytes(8,"000000000000"))
                        else
                            mfdata[sector*4+block] = resp
                        end
                    else
                        cp.log.error(string.format("Failed to read sector %2i, block %i, status code is %04x",sector,block,sw))
                        authenticated = false
                    end--if sw == 0x9000
                end--if authenticated
            end--for block
        end--if keylist
    end-- for
    return mfdata, mfuid
end

--
-- mifare_load_keys(keyfile) loads mifare keys from the file <keyfile>
-- The file <keyfile> is composed of lines of the form
--     n:k:hhhhhhhhhhhh
-- where 
--     * n represents a sector number or '*' for all sectors
--     * k is the letter 'a' or 'b' to describe the use of key A or B.
--     *  hhhhhhhhhhhh is the hexadecimal representation of the key
-- The file may also contain comments, which are prefixed with the '#'
-- character, as in bash and many other scripting languages.
--
function mifare_load_keys(keyfile)
    local keys = { }
    local fd, emsg = io.open(keyfile)
    local line_count = 0    
    local line, comment_pos
    local first, last
    local sector, sector_n, keytype, keyvalue
    local key_index = 0

    if not fd then
        cp.log.error(string.format("Failed to open key file %s",emsg))
        return nil
    end

    while true do
        line = fd:read("*line")
        if not line then break end
        line_count=line_count+1

        comment_pos = string.find(line,"#")
        if comment_pos~=nil then
            line = string.sub(line,1,comment_pos-1)
        end
        line = string.gsub(line,"[\t\r\v ]","")
    
        if string.len(line)~=0 then
            first, last, sector, keytype, keyvalue = string.find(line,"^([0-9*]+):([ABab]):(%x+)")

            keytype = string.lower(keytype)

            if not first then
                cp.log.error(string.format("%s[%d]: Syntax error in key entry format.",keyfile,line_count))
                fd:close() 
                return nil
            end

            if string.len(keyvalue)~=12 then
                cp.log.error(string.format("%s[%d]: Key is %d characters long, but should be 12 hexadicimal characters.",keyfile,line_count,string.len(keyvalue)))
                fd:close() 
                return nil
            end

            if sector=="*" then
                sector_n="default"
            else 
                sector_n = tonumber(sector)
                if not sector_n then
                    cp.log.error(string.format("%s[%d]: Unrecognized sector number '%s.'",keyfile,line_count,sector))
                    fd:close() 
                    return nil
                end
            end

            if keys[sector_n]==nil then
                keys[sector_n] = { }
            end
            table.insert(keys[sector_n], { keytype, keyvalue } )
        end--if line not empty 
    end--while
    fd:close() 
    return keys
end

function mifare_display_permissions(perms, data)
    access = mifare_access_permission_get(data,0)
    mifare_data_access(perms,0,access)
    
    access = mifare_access_permission_get(data,1)
    mifare_data_access(perms,1,access)
    
    access = mifare_access_permission_get(data,2)
    mifare_data_access(perms,2,access)
    
    access = mifare_access_permission_get(data,3)
    mifare_key_access(perms,access)
end

function mifare_display(root, mfdata, mfuid)

    util.node(root, "block", "UID", mfuid, string.format("%.0f", util.number(mfuid)))
	
	for sector=0,mfdata['last_sector'] do
        SECTOR = util.node(root, "record", "sector", nil, nil, sector)
        -- SECTOR:append{ classname="item", label="access key", val=util.bytes(8,key) }
        for block = 0,3 do
            local data = mfdata[sector*4+block]
            if data==nil then
                util.node(SECTOR, "block", "block", nil, "unaccessible", block)
            else
				ITEM = util.node(SECTOR, "block", "block", data, nil, block)
				if block == 3 then
                    mifare_trailer(ITEM,data)
                    PERMS = util.node(SECTOR, "block", "permissions")
                    mifare_display_permissions(PERMS,data)
                else
                    mifare_textify(ITEM,data)
                end
			end
		end
	end
end

--
-- START OF SCRIPT 
--

local use_defaults = true
do
  local ok, answer = pcall(cp.ui.question, "Try the public default MIFARE keys? Select No to load a key file.")
  if ok then use_defaults = answer end
end
local keys, mfdata, mfuid

keys = nil
if use_defaults then
    keys = MIFARE_STD_KEYS
else
    local ok, fname = pcall(cp.ui.file, "Load MIFARE key file", true)
    if ok and fname then keys = mifare_load_keys(fname) end
end

if keys==nil then

    cp.log.error("Aborted script: mifare key selection was cancelled.")

elseif true then

    CARD = apdu.start("Mifare")

    mfdata, mfuid = mifare_read_card(keys)
    if mfdata~=nil and mfuid~=nil then
        mifare_display(CARD, mfdata, mfuid)
    end    
end
