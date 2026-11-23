return function(CARD)
local function legacy_set(node,name,value) local fields={val='value',alt='alternative',id='identifier',classname='class'}; if name~='size' then node:set(fields[name] or name,value) end return node end
local function legacy_get(node,name) local fields={val='value',alt='alternative',id='identifier',classname='class'}; return node:get(fields[name] or name) end
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
-- 
-- ACKNOWLEDGEMENT:
-- The MOBIB "Event" parsing included in this file was build from
-- information found in public-domain software from Gildas Avoine, 
-- Tania Martin and Jean-Pierre Szikora from the Université catholique 
-- de Louvain, Belgium.


local cp = require('cardpeek')
local util = require('lib.util')
local en = require('lib.en1545')

require('etc.brussels-metro')
require('etc.brussels-bus')

function mobib_BIRTHDATE(source)
	local source_digits = source:convert(4)
	local year   = tonumber(util.sub(source_digits,0,3):to_hex())
	local month  = tonumber(util.sub(source_digits,4,5):to_hex())
	local day    = tonumber(util.sub(source_digits,6,7):to_hex())
	return os.date("%x",os.time({['year']=year,['month']=month,['day']=day}))
end

function mobib_GENDER(source)
	local n = util.number(source)
	if n==1 then
		return "Male"
	elseif n==2 then
		return "Female"
	end
	return "Unknown"
end

function mobib_HOLDERNUMBER(source)
	local source_digits = source:convert(4)
	return  tostring(util.sub(source_digits,0,5)).."/"..
		tostring(util.sub(source_digits,6,17)).."/"..
		tostring(util.sub(source_digits,18,18))
end


function mobib_TRANSPORT_BUS(source)
	local stationid = util.number(source)
	local retval = BRUSSELS_BUS[stationid]
	if retval then
		return retval
	end
	return "Unknown location"
end

function mobib_TRANSPORT_METRO(source)
	local stationid = util.number(source)
	local retval = BRUSSELS_METRO[stationid]
	if retval then
		return retval
	end
	return "Unknown location"
end

function mobib_TRANSPORT(source)
	local t = util.number(source)
	if t==0 then return "metro"
	elseif t==7 then return "premetro"
	elseif t==15 then return "bus"
	elseif t==22 then return "tramway"
	else return "UNKNOWN("..t..")"
	end
end

function mobib_process_block(ref,label,beginp,endp,block,func)
	local data = util.sub(block,beginp,endp)
	local res = func(data)
	ref:append{ classname="item",
	 	    label=label,
		    size=endp-beginp+1,
		    val=data,
		    alt=res }
	return res
end

function mobib_process_holderext(ref)
	local block = legacy_get(ref,"val"):convert(1)
	if bytes.is_all(block,0) then
		return false
	end
	mobib_process_block(ref,"HolderNumber",18,93,block,mobib_HOLDERNUMBER)
	mobib_process_block(ref,"HolderBirthRate",168,199,block,mobib_BIRTHDATE)
	mobib_process_block(ref,"HolderGender",200,201,block,mobib_GENDER)
	mobib_process_block(ref,"HolderName",205,359,block,en.alpha)
end

function mobib_process_event(ref)
	local block = legacy_get(ref,"val"):convert(1)
	local transport_type
	local ref2

	if bytes.is_all(block,0) then
		legacy_set(ref,"alt","NO EVENT RECORDED")
		return false
	end
	mobib_process_block(ref,"EventDataDateStamp",6,19,block,en.date)
	mobib_process_block(ref,"EventDataTimeStamp",20,30,block,en.time)
	mobib_process_block(ref,"EventDataDateFirstStamp",186,199,block,en.date)
	mobib_process_block(ref,"EventDataTimeFirstStamp",200,210,block,en.time)
	
	mobib_process_block(ref,"EventCountOfCoupons",139,161,block,en.number)
	transport_type = mobib_process_block(ref,"EventTransportType",99,103,block,mobib_TRANSPORT)
	if transport_type=="metro" or transport_type=="premetro" then
		mobib_process_block(ref,"EventLocationId",104,120,block,mobib_TRANSPORT_METRO)
		ref2 = ref:find_first({label="EventLocationId"})	
		mobib_process_block(ref2,"EventLocationZone",104,109,block,en.number)
		mobib_process_block(ref2,"EventLocationSubZone",110,113,block,en.number)
		mobib_process_block(ref2,"EventLocationStation",114,120,block,en.number)
	elseif transport_type=="bus" then
		mobib_process_block(ref,"EventLocationId",71,82,block,mobib_TRANSPORT_BUS)
		mobib_process_block(ref,"EventJourneyRoute",92,98,block,en.number)		
	end
	return true
end

function mobib_process_env(ref)
	local block = legacy_get(ref,"val"):convert(1)
	if bytes.is_all(block,0) then
		legacy_set(ref,"alt","NO ENVIRONMENT DATA")
	        return false
	end
	mobib_process_block(ref,"EnvNetworkId",13,36,block,en.network_id)
	return true
end

function mobib_process(cardenv)
	local record1_node
	local record2_node
	local data

	record1_node = cardenv:find_first({label="Holder Extended"}):find_first({label="record",id="1"})
	if record1_node==nil then 
		cp.log.error("Could not find record 1 in 'Holder Extended' file")
		return false
	end

	record2_node= cardenv:find_first({label="Holder Extended"}):find_first({label="record",id="2"})
	if record2_node==nil then 
		cp.log.error("Could not find record 2 in 'Holder Extended' file")
		return false
	end
	
	data = legacy_get(record1_node,"val") .. legacy_get(record2_node,"val")
	
	record1_node:remove()
	record2_node:remove()

	local node
	node = cardenv:find_first({label="Holder Extended"})
		      :append({ classname = "record", 
		                label = "record",
		      		id = "1+2",
		      		size = #data,
		      		val = data })
	mobib_process_holderext(node)

	for node in cardenv:find_first({label="Event logs"}):find({label="record"}) do
		mobib_process_event(node)
	end
	for node in cardenv:find_first({label="Environment"}):find({label="record"}) do
		mobib_process_env(node)
	end
end

mobib_process(CARD)



end
