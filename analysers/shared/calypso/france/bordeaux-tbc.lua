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
local en = require('shared.lib.en1545')
require('shared.calypso.france.bordeaux-lines')

SERVICE_PROVIDERS = {
  [21] = "TBC",
  [16] = "Transgironde"
}

TRANSITION_LIST = {  
  [1] = "Entrée",
  [6] = "Correspondance"
}

function navigo_process_events(ctx)
	local EVENTS
	local RECORD
	local REF
	local rec_index
	local code_value
	local route_number_value
	local vehicle_number_value
	local code_transport
	local code_transition
	local code_transport_string
	local code_transition_string
	local code_string
	local service_provider_value
	local location_id_value
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
	    service_provider_value = util.number(legacy_get(REF,"val"))
if service_provider_value == 21 then
TRANSPORT_LIST = {  
  [0] = "Information de mode de transport absente (ordinateur de bord non configuré)",
  [1] = "Tram",    
  [5] = "Bus" -- apparently bus, maybe tram B in some conditions, needs verification --> seems that a "lost" vehicle (without line information) is a bus by default.
}
else
TRANSPORT_LIST = {  
  [1] = "Car"
}
end	
	    legacy_set(REF,"alt",SERVICE_PROVIDERS[service_provider_value])
	    
	    REF = cp.nodes.find_first(RECORD,"EventRouteNumber")
	    route_number_value = util.number(legacy_get(REF,"val"))
	    if (route_number_value >= 1 and route_number_value <= 16) then
	    legacy_set(REF,"alt","Liane "..route_number_value)
	    else
		 if ((route_number_value >= 20 and route_number_value <= 30) or (route_number_value >= 62 and route_number_value <= 67) or (route_number_value >= 70 and route_number_value <=96)) then
	    legacy_set(REF,"alt","Ligne "..route_number_value)
	    else
		 if ((route_number_value >= 32 and route_number_value <= 37)) then
	    legacy_set(REF,"alt","Corol "..route_number_value)
	    else
		 if ((route_number_value == 38) or (route_number_value >= 48 and route_number_value <= 49) or (route_number_value == 68)) then
	    legacy_set(REF,"alt","Flexo "..route_number_value)
	    else
		 if ((route_number_value >= 51 and route_number_value <= 58) and not (route_number_value == 53) and not (route_number_value == 56)) then
	    legacy_set(REF,"alt","Flexo de nuit "..route_number_value)
	    else
		 if (route_number_value == 53 or route_number_value == 56) then
	    legacy_set(REF,"alt","Ligne "..route_number_value.." Express")
	    else
		 if (route_number_value == 59) then
	    legacy_set(REF,"alt","Ligne A")
	    else
		 if (route_number_value == 60) then
	    legacy_set(REF,"alt","Ligne B")
	    else
		 if (route_number_value == 61) then
	    legacy_set(REF,"alt","Ligne C")
	    else
		 if service_provider_value == 16 then
	    legacy_set(REF,"alt","Ligne "..route_number_value)
	    else
	    legacy_set(REF,"alt","Ligne inconnue (ou non définie dans l'ordinateur de bord au moment du badgeage)")
	    end
	    end
	    end
	    end
	    end
	    end
	    end
	    end
	    end

	    REF = cp.nodes.find_first(RECORD,"EventVehiculeId")
	    vehicle_number_value = util.number((legacy_get(REF,"val")))
	    legacy_set(REF,"alt","Véhicule n°"..vehicle_number_value)
	    
	    REF = cp.nodes.find_first(RECORD,"EventCode")
	    code_value = util.number(legacy_get(REF,"val"))

	    code_transport = rshift(code_value,4)
	    code_transport_string  = TRANSPORT_LIST[code_transport]
	    if code_transport_string==nil then code_transport_string = code_transport end

	    code_transition = band(code_value,0xF)
	    if (code_transition == 6) and (route_number_value == 0) then code_transition = 0 end
	    code_transition_string = TRANSITION_LIST[code_transition]
	    if (code_transition_string==nil) then code_transition_string = code_transition end

	    legacy_set(REF,"alt",code_transport_string.." - "..code_transition_string)
	    REF = cp.nodes.find_first(RECORD,"EventLocationId")
	       location_id_value = util.number(legacy_get(REF,"val"))
	    if location_id_value == 0 then legacy_set(REF,"alt","Aucun positionnement précis disponible")
	    else
	    if TRANSGIRONDE_STOPS_LIST[location_id_value] then
	    location_string = "arrêt "..TRANSGIRONDE_STOPS_LIST[location_id_value]
	    legacy_set(REF,"alt", location_string)
	    else
--	    legacy_set(REF,"alt", location_id_value)
	    legacy_set(REF,"alt", TRANSGIRONDE_STOPS_LIST[location_id_value])
	    end
	    end

	end
	end
end

navigo_process_events(CARD)



end
