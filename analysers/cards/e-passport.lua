-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id e-passport
-- @title ePassport
-- @description Inspect ICAO machine-readable travel documents with Basic Access Control
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
local util = require('shared.lib.util')
local tlv = require('cardpeek').tlv
local function band(a,b) return a & b end
local function bxor(a,b) return a ~ b end
local function rshift(a,b) return a >> b end
local function set_attribute(node,name,value)
  local fields={val='value',alt='alternative',id='identifier',['mime-type']='mime_type'}
  if name=='size' then return end
  node:set(fields[name] or name,value)
end
local function parse_tlv(parent,data,reference) return tlv.parse(parent,data,reference) end
local function notice(prompt) pcall(cp.ui.notice,prompt) end
local function readline(prompt) return cp.ui.text(prompt,'') end
local apdu = require('shared.lib.apdu')

local SSC
local KM_ENC
local KM_MAC
local KS_ENC
local KS_MAC
local TEST=false

function epass_check_digit(s, n)
    --The check digit calculation is as follows: each position is assigned a
    --value; for the digits 0 to 9 this is the value of the digits, for the
    --letters A to Z this is 10 to 35, for the filler < this is 0. The value of
    --each position is then multiplied by its weight; the weight of the first
    --position is 7, of the second it is 3, and of the third it is 1, and after
    --that the weights repeat 7, 3, 1, and so on. All values are added together
    --and the remainder of the final value divided by 10 is the check digit.
    local c = string.sub(s, n)
    local b = string.byte(c)
    local weights = {7, 3, 1}
    local weight = weights[(n-1) % 3 + 1]
    if (c == "<") then return 0 end
    if (b <= 58) then return (b - 48) * weight end
    return (b - 65) * weight
end

function epass_check_digits(s)
    local i = #s
    local cd = 0
    while i > 0 do
        cd = cd + epass_check_digit(s, i)
        --cp.log.info("Check digits after "..s.."["..i.."]: "..cd)
        i = i - 1
    end
    --cp.log.info("Check digits for "..s..": "..(cd%10))
    return cd % 10
end

function epass_inc_SSC()
	local i=7
	local e
	while i>=0 do
	   local values = SSC:elements()
	   values[i+1] = (values[i+1] + 1) & 0xFF
	   SSC = cp.bytes.pack(8, table.unpack(values))
	   if values[i+1]~=0 then break end
	   i=i-1
	end
	--print("SSC: ",#SSC,SSC)
	return true
end

function epass_key_derivation(seed)
	local SHA1
	local D
	local Kenc
	local Kmac

	SHA1 = nil
	D = cp.bytes.concat(seed, cp.bytes.pack(8,"00 00 00 01"))
        Kenc = cp.crypto.sha1(D)
        D = cp.bytes.concat(seed, cp.bytes.pack(8,"00 00 00 02"))
        Kmac = cp.crypto.sha1(D)
        return cp.bytes.sub(Kenc,0,15),cp.bytes.sub(Kmac,0,15)
end

function epass_create_master_keys(mrz_info)
	local hash
	local SHA1

	SHA1 = nil;
	hash = cp.crypto.sha1(cp.bytes.from_string(mrz_info))
	KM_ENC, KM_MAC = epass_key_derivation(cp.bytes.sub(hash,0,15))
	return true
end

function epass_create_session_keys()
	local sw, resp, response
	local rnd_icc
	local rnd_ifd
	local k_ifd =   cp.bytes.pack(8,"0B 79 52 40 CB 70 49 B0 1C 19 B3 3E 32 80 4F 0B")
	local S
	local iv = cp.bytes.pack(8,"00 00 00 00 00 00 00 00")


	local e_ifd
	local m_ifd

	rnd_ifd = cp.bytes.pack(8,"01 23 45 67 89 AB DC FE")
	response = util.transmit(cp.bytes.pack(8,"00 84 00 00 08"))
	sw, rnd_icc = response.status, response.data

	if (sw~=0x9000) then return false end
	S = rnd_ifd .. rnd_icc .. k_ifd
	e_ifd = cp.crypto.des_ede3_cbc(true,KM_ENC,iv,S)
	m_ifd = cp.crypto.iso9797_mac(KM_MAC,e_ifd)
	cmd_data = e_ifd..m_ifd

	response = util.transmit(cp.bytes.pack(8,"00 82 00 00 28",cmd_data,0x28))
	sw, resp = response.status, response.data

	if (sw==0x6300) then
	   	cp.log.warning("Perhaps you didn't enter the right MRZ data for this passport")
        end
	if (sw~=0x9000) then
		return false
	end
	R = cp.crypto.des_ede3_cbc(false,KM_ENC,iv,cp.bytes.sub(resp,0,31))
	k_icc = cp.bytes.sub(R,16,31)
	k_seed = cp.bytes.pack(8)
	for i=0,15 do
	    k_seed = cp.bytes.concat(k_seed,bxor(cp.bytes.get(k_ifd,i),cp.bytes.get(k_icc,i)))
	end
	SSC = cp.bytes.sub(rnd_icc,4,7)..cp.bytes.sub(rnd_ifd,4,7)
	KS_ENC, KS_MAC = epass_key_derivation(k_seed)
	return true
end

function epass_select(EF)
	local cmdheader = cp.bytes.pack(8,"0C A4 02 0C")
	local cmdbody   = cp.bytes.pack(8,rshift(EF,8),band(EF,0xFF))


	local iv = cp.bytes.pack(8,"00 00 00 00 00 00 00 00")
	local DO87, DO8E
	local command
	local DO99

	local padded_body = cmdbody .. cp.bytes.from_hex('80')
	while #padded_body % 8 ~= 0 do padded_body = padded_body .. cp.bytes.from_hex('00') end
	M = cp.bytes.concat("01",cp.crypto.des_ede3_cbc(true,KS_ENC,iv,padded_body))
	DO87 = cp.asn1.join(0x87,M)
	epass_inc_SSC()
	N = cp.bytes.concat(SSC,cmdheader,"80 00 00 00",DO87)
	CC = cp.crypto.iso9797_mac(KS_MAC,N)
	DO8E = cp.asn1.join(0x8E,cp.crypto.iso9797_mac(KS_MAC,N))
	command=cp.bytes.concat(cmdheader,(#DO87+#DO8E),DO87,DO8E,0)
	response = util.transmit(command)
	sw, resp = response.status, response.data
	epass_inc_SSC()
	if sw~=0x9000 then
		return sw, resp
	end
	tag_99, value_99, rest = cp.asn1.split(resp)
	tag_8E, value_8E, rest = cp.asn1.split(rest)
	if tag_99~=0x99 then
	   cp.log.warning("Expected tag 99 in card response")
	   return 0x6FFF
	end
	if tag_8E~=0x8E then
           cp.log.warning("Expected tag 8E in card response")
           return 0x6FFF
        end
	sw = 0+cp.bytes.number(value_99)

	N = SSC..cp.asn1.join(tag_99,value_99)

	CC = cp.crypto.iso9797_mac(KS_MAC,N)
	if value_8E~=CC then
	   cp.log.warning("Failed to verify MAC in response")
        end
	return sw, resp
end

function epass_read_binary(start,len)
	local cmdheader = cp.bytes.pack(8,"0C B0", rshift(start,8),band(start,0xFF))


	local DO97,D08E
	local value_87
	local iv = cp.bytes.pack(8,"00 00 00 00 00 00 00 00")

	DO97 = cp.bytes.pack(8,0x97,01,len)
	epass_inc_SSC()
	DO8E = cp.asn1.join(0x8E,cp.crypto.iso9797_mac(KS_MAC,cp.bytes.concat(SSC,cmdheader,"80 00 00 00",DO97)))
	command = cp.bytes.concat(cmdheader,(#DO97+#DO8E),DO97,DO8E,0)
	response = util.transmit(command)
	sw, resp = response.status, response.data
	epass_inc_SSC()
	if (sw~=0x9000) and (sw~=0x6282) then return false end
	tag_87, value_87 = cp.asn1.split(resp)
	decrypted_data = cp.crypto.des_ede3_cbc(false,KS_ENC,iv,cp.bytes.sub(value_87,1,-1))
	return sw, cp.bytes.sub(decrypted_data,0,len-1)
end

function epass_read_file()
	sw,resp = epass_read_binary(0,4)
	if sw~=0x9000 then return nil end
	cp.log.info("Heading is " .. tostring(resp))
	tag, rest = cp.asn1.split_tag(resp)
	len, rest = cp.asn1.split_length(rest)

	--io.write("read_file: [")

	if len>127 then
           to_read = len + 2 + cp.bytes.get(resp,1)-128
	else
           to_read = len + 2
	end

	cp.log.info("Expecting " .. to_read)
	result = cp.bytes.pack(8)
	already_read = 0
	while to_read>0 do
	     --io.write(".");io.flush()
	     if to_read>0x80 then
	        le = 0x80
             else
	        le = to_read
	     end
	     sw, resp = epass_read_binary(already_read,le)
	     if sw~=0x9000 then return result end
	     result = cp.bytes.concat(result,resp)
	     already_read = already_read + #resp
	     to_read = to_read - #resp
	end
	--io.write("] "..#result.."bytes\n")
	return result
end

function ui_parse_version(node,data)
	local ver = cp.bytes.format(cp.bytes.sub(data,0,1),"%P")
	local i
	for i=1,(#data/2)-1 do
		ver = ver .. "." .. cp.bytes.format(cp.bytes.sub(data,i*2,i*2+1),"%P")
	end
	set_attribute(node,"val",data)
	set_attribute(node,"alt",ver)
	return true
end



function ui_parse_cstring(node,data)
	set_attribute(node,"val",data)
	if #data>1 then
  set_attribute(node,"alt",cp.bytes.format(cp.bytes.sub(data,0,#data-2),"%P"))
	end
end

function ui_parse_utf8(node,data)
	set_attribute(node,"val",data)

	if #data==0 then
		return false
	end

	local alt = cp.bytes.format(data,"%C")
	if not cp.bytes.printable(data) then
		alt = cp.bytes.format(data,"%C (%D)")
	end
        set_attribute(node,"alt",alt)
	return true
end

BL_FAC_RECORD_HEADER = {
	{ "Format Identifier", 4, ui_parse_cstring },
	{ "Format Version", 4, ui_parse_cstring },
	{ "Length of Record", 4, tlv.parsers.number },
	{ "Number of Faces", 2, tlv.parsers.number }
}

BL_FAC_INFORMATION = {
	{ "Face Image Block Length", 4, tlv.parsers.number },
	{ "Number of Feature Points", 2, tlv.parsers.number },
	{ "Gender", 1 , {
		[0]="Unspecified",
		[1]="Male",
		[2]="Female",
		[3]="Unknown" }},
	{ "Eye Color", 1, {
		[0]="Unspecified",
                [1]="Black",
                [2]="Blue",
                [3]="Brown",
                [4]="Gray",
                [5]="Green",
                [6]="Multi-Coloured",
                [7]="Pink",
                [8]="Other or Unknown" }},
	{ "Hair Color", 1 , {
		[0]="Unspecified",
                [1]="Bald",
                [2]="Black",
                [3]="Blonde",
                [4]="Brown",
                [5]="Gray",
                [6]="White",
                [7]="Red",
                [8]="Green",
                [9]="Blue",
                [255]="Other or Unknown" }},
	{ "Feature Mask", 3 },
	{ "Expression", 2, {
		[0]="Unspecified",
                [1]="Neutral",
                [2]="Smile with closed mouth",
                [3]="Smile with open mouth",
                [4]="Raised eyebrows",
                [5]="Eyes looking away",
                [6]="Squinting",
                [7]="Frowning" }},
	{ "Pose Angle", 3 },
	{ "Pose Angle Uncertainty", 3 }
}

BL_FAC_FEATURE_POINT = {
	{ "Feature Type", 1 },
	{ "Feature Point", 1 },
	{ "Horizontal Position (x)", 2 },
	{ "Vertical Position (y)", 2 },
	{ "Reserved", 2 }
}

BL_FAC_IMAGE_INFORMATION = {
	{ "Face Image Type", 1 },
	{ "Image Data Type", 1 },
	{ "Width", 2, tlv.parsers.number },
	{ "Height", 2, tlv.parsers.number },
	{ "Image Color Space", 1 },
	{ "Source Type", 1 },
	{ "Device Type", 2 },
	{ "Quality", 2 }
}

BL_FIR_GENERAL_RECORD_HEADER = {
	{ "Format Identifier", 4, ui_parse_cstring },
	{ "Version Number", 4, ui_parse_cstring },
	{ "Record Length", 6, tlv.parsers.number },
	{ "Vendor ID", 2 },
	{ "Scanner ID", 2 },
	{ "Number of fingers/palms", 1, tlv.parsers.number },
	{ "Scale Units", 1 },
	{ "Horizontal Scan Resolution", 2, tlv.parsers.number },
	{ "Vertical Scan Resolution", 2, tlv.parsers.number },
	{ "Horizontal Image Resolution", 2, tlv.parsers.number },
	{ "Vertical Image Resolution", 2, tlv.parsers.number },
	{ "Pixel Depth", 1 },
	{ "Image Compression Algorithm", 1, {
		[1]="Uncompressed – bit packed",
		[2]="Compressed – WSQ",
		[3]="Compressed – JPEG",
		[4]="Compressed – JPEG2000",
		[5]="PNG" }},
	{ "Reserved", 2 }
}

BL_FIR_IMAGE_RECORD_HEADER = {
	{ "Length of finger data block", 4, tlv.parsers.number },
	{ "Finger/palm position", 1, {
		[0]="Unknown",
		[1]="Right thumb",
		[2]="Right index finger",
		[3]="Right middle finger",
		[4]="Right ring finger",
		[5]="Right little finger",
		[6]="Left thumb",
		[7]="Left index finger",
		[8]="Left middle finger",
		[9]="Left ring finger",
		[10]="Left little finger",
		[11]="Plain right thumb",
		[12]="Plain left thumb",
		[13]="Plain right four fingers",
		[14]="Plain left four fingers",
		[15]="Plain thumbs (2)"	}},
	{ "Count of views", 1, tlv.parsers.number },
	{ "View number", 1, tlv.parsers.number },
	{ "Finger/palm image quality", 1 },
	{ "Impression type", 1 },
	{ "Horizontal line length", 2, tlv.parsers.number },
	{ "Vertical line length", 2, tlv.parsers.number },
	{ "Reserved", 1 }
}


function ui_parse_block(node,format,data,pos)
	local ITEM
	local block
	local i,v
	local index

	for i,v in ipairs(format) do
		ITEM = node:append({ classname="item", label=v[1], id=i-1, size=v[2] })
		block = cp.bytes.sub(data,pos,pos+v[2]-1)
		if v[3]~=nil then
			if type(v[3])=="function" then
			   if v[3](ITEM,block)==false then
			      return nil
			   end
			elseif type(v[3])=="table" then
			   index = cp.bytes.number(block)
			   set_attribute(ITEM,"val",block)
			   if v[3][index] then
				set_attribute(ITEM,"alt",v[3][index])
			   else
				set_attribute(ITEM,"alt",index)
			   end
			else
			   return nil
			end
		else
			set_attribute(ITEM,"val",block)
		end
		pos = pos + v[2]
	end
	return pos
end

FAC_FORMAT_IDENTIFIER = cp.bytes.pack(8,"46414300")
FIR_FORMAT_IDENTIFIER = cp.bytes.pack(8,"46495200")

function ui_parse_biometry_fac(node,data)
	local BLOCK
	local SUBBLOCK
	local SUBSUBBLOCK
	local SUBSUBSUBBLOCK
	local index = 0
	local num_faces
	local num_features
	local block_length
	local block_start
	local image_len
	local i,j

	num_faces = cp.bytes.number(cp.bytes.sub(data,12,13))

	BLOCK = node:append({ classname="item", label="Facial Record Header" })
	index = ui_parse_block(BLOCK,BL_FAC_RECORD_HEADER,data,index)
	if index==nil then
		cp.log.error("Failed to parse facial header information")
		return false
	end

	BLOCK = node:append({ classname="item", label="Facial Data Records" })

	for i = 1,num_faces do
		block_start = index
		block_length = cp.bytes.number(cp.bytes.sub(data,index,index+3))
		num_features = cp.bytes.number(cp.bytes.sub(data,index+4,index+5))

		SUBBLOCK = BLOCK:append({ classname="item", label="Facial Record Data", id=i, size=block_length })

		SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Facial Information" })
		index = ui_parse_block(SUBSUBBLOCK,BL_FAC_INFORMATION,data,index)
		if index==nil then
			cp.log.error("Failed to parse facial information")
			return false
		end

		if num_features>0 then
			SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Feature points" })
			for j=1,num_features do
				SUBSUBSUBBLOCK =  node:append({ classname="item", label="Feature Point", id=j })
				index = ui_parse_block(SUBSUBSUBBLOCK,BL_FEATURE_POINT,data,index)
				if index==nil then
					cp.log.error("Failed to parse facial feature information")
					return false
				end
			end
		end

		SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Image Information" })
		index = ui_parse_block(SUBSUBBLOCK,BL_FAC_IMAGE_INFORMATION,data,index)
		if index==nil then
			cp.log.error("Failed to parse facial image information")
			return false
		end

		image_len = block_length-(index-block_start)
		SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Image Data", size=image_len })
		set_attribute(SUBSUBBLOCK,"val",cp.bytes.sub(data,index,index+image_len-1))

        if image_len>2 and cp.bytes.sub(data,index,index+1) == cp.bytes.pack(8,"FF D8") then
		    set_attribute(SUBSUBBLOCK,"mime-type","image/jpeg")
	    elseif image_len>6 and cp.bytes.sub(data,index,index+5) == cp.bytes.pack(8,"00 00 00 0C 6A 50") then
		    set_attribute(SUBSUBBLOCK,"mime-type","image/jp2")
        else
            cp.log.warning("Could not identify facial image format.")
        end

        index = index + image_len
	end
	return true

end

function ui_parse_biometry_fir(node,data)
        local BLOCK
        local SUBBLOCK
        local SUBSUBBLOCK
        local index = 0
	local num_images
	local record_size
	local record_start
	local image_size
	local i

	BLOCK = node:append({ classname="item", label="Finger General Record Header" })
	index = ui_parse_block(BLOCK,BL_FIR_GENERAL_RECORD_HEADER,data,index)
	if index==nil then
		cp.log.error("Failed to parse finger general record header information")
		return false
	end
	num_images = cp.bytes.number(cp.bytes.sub(data,18,18))

	BLOCK = node:append({ classname="item", label="Finger Images" })
	for i=1,num_images do
		record_size = cp.bytes.number(cp.bytes.sub(data,index,index+3))
		record_start = index

		SUBBLOCK = BLOCK:append({ classname="item", label="Finger Image", id=i, size=record_size })
		SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Finger Image Record Header" })
		index = ui_parse_block(SUBSUBBLOCK,BL_FIR_IMAGE_RECORD_HEADER,data,index)
		if index==nil then
			cp.log.error("Failed to parse finger image record header information")
			return false
		end

		image_size = record_size-(index-record_start)
		SUBSUBBLOCK = SUBBLOCK:append({ classname="item", label="Finger Image Data" })
		set_attribute(SUBSUBBLOCK,"val",cp.bytes.sub(data,index,index+image_size-1))
		index = index + image_size
	end

	return true
end

function ui_parse_biometry(node,data)
	local tag = cp.bytes.sub(data,0,3)

	if tag==FAC_FORMAT_IDENTIFIER then
		ui_parse_biometry_fac(node,data)
	elseif tag==FIR_FORMAT_IDENTIFIER then
		ui_parse_biometry_fir(node,data)
	else
		set_attribute(node,"val",data)
	end
	return true
end

function ui_parse_jpeg(node,data)
	set_attribute(node,"val", data)
	if cp.bytes.sub(data,1,2) == cp.bytes.pack(8,"D8 FF") then
		set_attribute(node,"mime-type","image/jpeg")
	end
	return true
end


AID_MRTD = "#A0000002471001"

MRP_REFERENCE = {
   ['5F01']   = { "LDS Version Number", ui_parse_version },
   ['5F08']   = { "Date of birth (truncated)" },
   ['5F0E']   = { "Full name, in national characters", ui_parse_utf8 },
   ['5F0F']   = { "Other names", tlv.parsers.printable },
   ['5F10']   = { "Personal Number", tlv.parsers.printable },
   ['5F11']   = { "Place of birth", ui_parse_utf8 },
   ['5F12']   = { "Telephone", tlv.parsers.printable },
   ['5F13']   = { "Profession", tlv.parsers.printable },
   ['5F14']   = { "Title", tlv.parsers.printable },
   ['5F15']   = { "Personal Summary", tlv.parsers.printable },
   ['5F16']   = { "Proof of citizenship (10918 image)", ui_parse_jpeg },
   ['5F17']   = { "Other valid TD Numbers" },
   ['5F18']   = { "Custody information", tlv.parsers.printable },
   ['5F19']   = { "Issuing Authority", ui_parse_utf8 },
   ['5F1A']   = { "Other people on document" },
   ['5F1B']   = { "Endorsement/Observations", tlv.parsers.printable },
   ['5F1C']   = { "Tax/Exit requirements", tlv.parsers.printable },
   ['5F1D']   = { "Image of document front", ui_parse_jpeg },
   ['5F1E']   = { "Image of document rear", ui_parse_jpeg },
   ['5F1F']   = { "MRZ data elements", tlv.parsers.printable },
   ['5F26']   = { "Date of Issue" },
   ['5F2B']   = { "Date of birth (8 digit)" },
   ['5F2E']   = { "Biometric data block", ui_parse_biometry },
   ['5F36']   = { "Unicode Version number", ui_parse_version },
   ['5F40']   = { "Compressed image template", ui_parse_jpeg },
   ['5F42']   = { "Address", tlv.parsers.printable },
   ['5F43']   = { "Compressed image template", ui_parse_jpeg },
   ['5F50']   = { "Date data recorded" },
   ['5F51']   = { "Name of person", ui_parse_utf8 },
   ['5F52']   = { "Telephone", tlv.parsers.printable },
   ['5F53']   = { "Address", tlv.parsers.printable },
   ['5F55']   = { "Date and time document personalized" },
   ['5F56']   = { "Serial number of personalization system" },
   ['60']     = { "Common Data Elements" },
   ['61']     = { "Template for MRZ Data Group" },
   ['63']     = { "Template for finger biometric Data Group" },
   ['65']     = { "Template for digitized facial image" },
   ['67']     = { "Template for digitized signature or usual mark" },
   ['68']     = { "Template for machine assisted security -- Encoded data" },
   ['69']     = { "Template for machine assisted security -- Structure" },
   ['6A']     = { "Template for machine assisted security -- Substance" },
   ['6B']     = { "Template for additional personal details" },
   ['6C']     = { "Template for additional document details" },
   ['6D']     = { "Optional details" },
   ['6E']     = { "Reserved for future use" },
   ['70']     = { "Person to notify" },
   ['75']     = { "Template for facial biometric Data Group" },
   ['76']     = { "Template for iris (eye) biometric template" },
   ['77']     = { "Security data (CMD/RFC 3369)" },
   ['7F2E']   = { "Biometric data block (enciphered)" },
   ['7F60']   = { "Biometric Information Template" },
   ['7F61']   = { "Biometric Information Group Template" },
   ['7F61/2'] = { "Number of instances" },
   ['A1']     = { "Biometric Header Template" },
   ['A1/80']  = { "ICAO header version" },
   ['A1/81']  = { "Biometric type" },
   ['A1/82']  = { "Biometric feature" },
   ['A1/83']  = { "Creation date and time" },
   ['A1/84']  = { "Validity period" },
   ['A1/86']  = { "Creator of the biometric reference data (PID)" },
   ['A1/87']  = { "Format owner" },
   ['A1/88']  = { "Format type" }
}



FILES = {
  { ['FID']=0x011E, ['name']='EF.COM' },
  { ['FID']=0x0101, ['name']='EF.DG1' },
  { ['FID']=0x0102, ['name']='EF.DG2' },
  { ['FID']=0x0103, ['name']='EF.DG3' },
  { ['FID']=0x0104, ['name']='EF.DG4' },
  { ['FID']=0x0105, ['name']='EF.DG5' },
  { ['FID']=0x0106, ['name']='EF.DG6' },
  { ['FID']=0x0107, ['name']='EF.DG7' },
  { ['FID']=0x0108, ['name']='EF.DG8' },
  { ['FID']=0x0109, ['name']='EF.DG9' },
  { ['FID']=0x010A, ['name']='EF.DG10' },
  { ['FID']=0x010B, ['name']='EF.DG11' },
  { ['FID']=0x010C, ['name']='EF.DG12' },
  { ['FID']=0x010D, ['name']='EF.DG13' },
  { ['FID']=0x010E, ['name']='EF.DG14' },
  { ['FID']=0x010F, ['name']='EF.DG15' },
  { ['FID']=0x0110, ['name']='EF.DG16' },
  { ['FID']=0x011D, ['name']='EF.SOD' }
}

local function prompt(prompt)
  local ok, value = pcall(cp.ui.text, prompt, '')
  return ok and value or ''
end

local pass_no = prompt('Enter document id or passport number')
pass_no = string.upper(pass_no)
while #pass_no < 9 do pass_no = pass_no .. '<' end
if #pass_no == 9 then pass_no = pass_no .. epass_check_digits(pass_no) end
local pass_bd = prompt('Enter birth date YYMMDD') .. ''
local pass_ed = prompt('Enter expiration date YYMMDD') .. ''
if #pass_bd == 6 then pass_bd = pass_bd .. epass_check_digits(pass_bd) end
if #pass_ed == 6 then pass_ed = pass_ed .. epass_check_digits(pass_ed) end
MRZ_DATA = pass_no .. pass_bd .. pass_ed

local root = apdu.start('e-passport')
if #MRZ_DATA ~= 24 then
  util.node(root, 'item', 'Invalid passport access data', nil, 'Enter a document number and two six-digit dates')
  return
end

local response = apdu.select(AID_MRTD, 0)
local app = util.node(root, 'application', 'ePassport application', nil, nil, AID_MRTD:sub(2))
if response.status ~= 0x9000 then
  util.node(app, 'item', 'Application selection failed', response.data, string.format('%04X', response.status))
  return
end
if #response.data > 0 then parse_tlv(app, response.data) end

epass_create_master_keys(MRZ_DATA)
if not epass_create_session_keys() then
  util.node(app, 'item', 'Basic Access Control failed', nil, 'Check the passport access data')
  return
end

for _, file in ipairs(FILES) do
  cp.log.info('Attempt to select ' .. file.name)
  local sw, select_data = epass_select(file.FID)
  local file_node = util.node(app, 'file', file.name, nil, nil, string.format('%04X', file.FID))
  util.node(file_node, 'header', 'Secure SELECT response', select_data)
  local content = util.node(file_node, 'body', 'content')
  if sw == 0x9000 then
    local data = epass_read_file()
    if data then
      if cp.bytes.get(data, 0) == 0x6D then
        local _, value = cp.asn1.split(data)
        util.node(content, 'item', 'National specific data', value)
      else
        parse_tlv(content, data, MRP_REFERENCE)
      end
    else
      content:set('alternative', 'Selected file, but data is not accessible')
    end
  else
    content:set('alternative', string.format('Content not accessible (code %04X)', sw))
  end
end
