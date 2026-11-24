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

local cp = require('cardpeek')
local util = require('shared.lib.util')
local en = require('cardpeek').en1545

SERVICE_PROVIDERS = {
  [5] = "TAM"
}

TRANSPORT_LIST = {  
  [1] = "Urban Bus",  
  [2] = "Interurban Bus",  
  [3] = "Metro",  
  [4] = "Tram",  
  [5] = "Train",  
  [8] = "Parking"
}

TRANSITION_LIST = {  
  [1] = "Entry",  
  [2] = "Exit",  
  [4] = "Inspection",  
  [6] = "Interchange (entry)",  
  [7] = "Interchange (exit)"
}

function process_events(cardenv,node_label)
    local event_node
    local record_node
    local ref_node

    local code_value
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

    event_node = cardenv:find_first({label=node_label, parsed="true"})

    if event_node==nil then 
       cp.log.warning("No " .. node_label .. " found in card")
       return 0 
    end

    for record_node in event_node:find({label="record"}) do

        -- is it TAM?
        ref_node = record_node:find_first({label="EventServiceProvider"})
        service_provider_value = cp.bytes.number(legacy_get(ref_node,"val"))
        legacy_set(ref_node,"alt",SERVICE_PROVIDERS[service_provider_value])

        ref_node = record_node:find_first({label="EventCode"})
        code_value = cp.bytes.number(legacy_get(ref_node,"val"))

        -- is it a bus, a tram, ...?
        code_transport = rshift(code_value,4)
        code_transport_string  = TRANSPORT_LIST[code_transport]
        if code_transport_string==nil then code_transport_string = code_transport end

        -- is it an entry, an exit, ...?
        code_transition = band(code_value,0xF)
        code_transition_string = TRANSITION_LIST[code_transition]   
        if (code_transition_string==nil) then code_transition_string = code_transition end

        legacy_set(ref_node,"alt",code_transport_string.." - "..code_transition_string)
    end
end

process_events(CARD,"Event logs")

end
