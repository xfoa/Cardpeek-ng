return function(CARD)
local function legacy_set(node,name,value) local fields={val='value',alt='alternative',id='identifier',classname='class'}; if name~='size' then node:set(fields[name] or name,value) end return node end
local function legacy_get(node,name) local fields={val='value',alt='alternative',id='identifier',classname='class'}; return node:get(fields[name] or name) end
--
-- This file is part of Cardpeek, the smartcard reader utility.
--
-- Copyright 2009 by 'L1L1' and 2013-2014 by 'kalon33'
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

---------------------------------------------------------------------
-- Most of the data and coding ideas in this file 
-- was contributed by 'Pascal Terjan', based on location 
-- data from 'Nicolas Derive'.
---------------------------------------------------------------------

local cp = require('cardpeek')
local util = require('shared.lib.util')
local en = require('cardpeek').en1545
require('shared.calypso.france.grenoble-tag-stops')
require('shared.calypso.france.grenoble-tag-lines')

SERVICE_PROVIDERS = {
  [3] = "TAG"
}

TRANSPORT_LIST = {  
  [1] = "Tram"  
}

TRANSITION_LIST = {  
  [1] = "Entry",  
  [2] = "Exit",  
  [4] = "Inspection",  
  [6] = "Interchange (entry)",  
  [7] = "Interchange (exit)"
}

function navigo_process_events(ctx)
	local EVENTS
	local RECORD
	local REF
	local rec_index
	local code_value
	local code_transport
	local code_transition
	local code_transport_string
	local code_transition_string
	local code_string
	local service_provider_value
	local location_id_value
	local route_number_value
	local route_string
	local sector_id
	local station_id
	local location_string

	EVENTS = cp.nodes.find_first(ctx,"Event logs, parsed");
	if EVENTS==nil then 
	   cp.log.warning("No event found in card")
	   return 0 
	end

	for rec_index=1,16 do
	    RECORD = cp.nodes.find_first(EVENTS,"record",rec_index)
	    if RECORD==nil then break end
	    
	    REF = cp.nodes.find_first(RECORD,"EventServiceProvider")
	    service_provider_value = cp.bytes.number(legacy_get(REF,"val"))
	    legacy_set(REF,"alt",SERVICE_PROVIDERS[service_provider_value])
	    
	    REF = cp.nodes.find_first(RECORD,"EventCode")
	    code_value = cp.bytes.number(legacy_get(REF,"val"))

	    code_transport = rshift(code_value,4)
	    code_transport_string  = TRANSPORT_LIST[code_transport]
	    if code_transport_string==nil then code_transport_string = code_transport end

	    code_transition = band(code_value,0xF)
	    code_transition_string = TRANSITION_LIST[code_transition]
	    if (code_transition_string==nil) then code_transition_string = code_transition end

	    legacy_set(REF,"alt",code_transport_string.." - "..code_transition_string)

	    if service_provider_value == 3 and code_transport <=1 then
	       REF = cp.nodes.find_first(RECORD,"EventLocationId")
	       location_id_value = cp.bytes.number(legacy_get(REF,"val"))
--	       sector_id = rshift(location_id_value,9)
--	       station_id = band(rshift(location_id_value,4),0x1F)

--	             if STOPS_LIST[sector_id]~=nil then
--		        location_string = "secteur "..STOPS_LIST[sector_id]['name'].." - station "
--			if STOPS_LIST[sector_id][station_id]==nil then
--                           location_string = location_string .. station_id
--	                else
--                           location_string = location_string .. STOPS_LIST[sector_id][station_id]
--                        end
--		     else
--		        location_string = "secteur "..sector_id.." - station "..station_id
--		     end
--	       end
		if STOPS_LIST[location_id_value]~=nil then
			location_string = STOPS_LIST[location_id_value]
		else
	       		location_string = location_id_value
		end
               legacy_set(REF,"alt",location_string)

	     REF = cp.nodes.find_first(RECORD,"EventRouteNumber")
	     route_number_value = cp.bytes.number(legacy_get(REF,"val"))
	     if LINES_LIST[route_number_value]["name"] then
	     	route_string = LINES_LIST[route_number_value]["name"]
	     else
--		route_string = route_number_value
	     	route_string = LINES_LIST[route_number_value]["name"]
	     end
	     legacy_set(REF,"alt",route_string)
	    end
	end
end

navigo_process_events(CARD)



end
