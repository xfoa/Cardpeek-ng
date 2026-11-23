return function(CARD)
local function legacy_set(node,name,value) local fields={val='value',alt='alternative',id='identifier',classname='class'}; if name~='size' then node:set(fields[name] or name,value) end return node end
local function legacy_get(node,name) local fields={val='value',alt='alternative',id='identifier',classname='class'}; return node:get(fields[name] or name) end
--
-- This file is part of Cardpeek, the smartcard reader utility.
--
-- Copyright 2009-2011 by 'L1L1'
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

-------------------------------------------------------------------------
-- *PLEASE NOTE*
-- This work is based on:
-- * public information about the calypso card specification, 
-- * partial information found on the web about the ticketing data 
--   format, as described in the French "intercode" documentation.
-- * experimentation and guesses, 
-- This information is incomplete. If you have further data, such 
-- as details of ISO 1545 or calypso card specs, please help send them
-- to L1L1@gmx.com
--------------------------------------------------------------------------

local cp = require('cardpeek')
local util = require('shared.lib.util')
local en = require('shared.lib.en1545')

local card_num = require('shared.calypso.card-number')

intercode_Contract = {}
intercode_Contract_types = {} -- list of contract types (detected by BestContracts structure)
intercode_Contract_pointers = {} -- list of contract pointers (detected by BestContracts structure)

function intercode_parse_best_contract_tariff(source)
    local sort_key = util.number(util.sub(source, 0, 3))
    local contract_type = util.number(util.sub(source, 4, 11))
    local priority = util.number(util.sub(source, 12, 15))
    table.insert(intercode_Contract_types, contract_type)
    return "Sort key: "..sort_key.." - Contract type: "..string.format('%02Xh', contract_type).." - Priority: "..priority
end

function intercode_parse_best_contract_pointer(source)
    local pointer = util.number(source)
    table.insert(intercode_Contract_pointers, pointer)
    return tostring(pointer)
end

intercode_Env = {
    [0] = { en.undefined, 6, "EnvApplicationVersionNumber" },
    [1] = { en.BITMAP, 7, "Env", {
        [0] = { en.network_id, 24, "EnvNetworkId" },
        [1] = { en.undefined, 8, "EnvApplicationIssuerId" },
        [2] = { en.date, 14, "EnvApplicationValidityEndDate" },
        [3] = { en.undefined, 11, "EnvPayMethod" },
        [4] = { en.undefined, 16, "EnvAuthenticator" },
        [5] = { en.undefined, 32, "EnvSelectList" },
        [6] = { en.BITMAP, 2, "EnvData", {
            [0] = { en.undefined, 1, "EnvCardStatus" },
            [1] = { en.undefined, 0, "EnvData2" },
        }}
    }}
}

intercode_Holder = {
    [0] = { en.BITMAP, 8, "Holder", {
        [0] = { en.BITMAP, 2, "HolderName", {
            [0] = { en.undefined, 85, "HolderSurname" },
            [1] = { en.undefined, 85, "HolderForename" }
        }},
        [1] = { en.BITMAP, 2, "HolderBirth", {
            [0] = { en.bcd_date, 32, "HolderBirthDate" },
            [1] = { en.undefined, 115, "HolderBirthPlace"}
        }},
        [2] = { en.undefined, 85, "HolderBirthName" },
        [3] = { en.undefined, 32, "HolderIdNumber" },
        [4] = { en.undefined, 24, "HolderCountryAlpha" },
        [5] = { en.undefined, 32, "HolderCompany" },
        [6] = { en.REPEAT, 4, "HolderProfiles", {
            [0] = { en.BITMAP, 3, "Profile", {
                [0] = { en.undefined, 24, "NetworkId" },
                [1] = { en.number, 8, "ProfileNumber" },
                [2] = { en.date, 14, "ProfileDate" }
            }}
        }},
        [7] = { en.BITMAP, 12, "HolderData", {
            [0] = { en.undefined, 4, "HolderDataCardStatus" },
            [1] = { en.undefined, 4, "HolderDataTeleReglement" },
            [2] = { en.undefined, 17, "HolderDataResidence" },
            [3] = { en.undefined, 6, "HolderDataCommercialID" },
            [4] = { en.undefined, 17, "HolderDataWorkPlace" },
            [5] = { en.undefined, 17, "HolderDataStudyPlace" },
            [6] = { en.undefined, 16, "HolderDataSaleDevice" },
            [7] = { en.undefined, 16, "HolderDataAuthenticator" },
            [8] = { en.undefined, 14, "HolderDataProfileStartDate1" },
            [9] = { en.undefined, 14, "HolderDataProfileStartDate2" },
            [10] = { en.undefined, 14, "HolderDataProfileStartDate3" },
            [11] = { en.undefined, 14, "HolderDataProfileStartDate4" }
        }}
    }}
}

intercode_BestContracts = {
    [0] = { en.REPEAT, 4, "BestContracts", {
        [0] = { en.BITMAP, 3, "BestContract", {
            [0] = { en.network_id, 24, "BestContractNetworkId" },
            [1] = { intercode_parse_best_contract_tariff, 16, "BestContractTariff" },
            [2] = { intercode_parse_best_contract_pointer, 5, "BestContractPointer" },
        }},
    }},
}

intercode_Contract['FFh'] = {
    [0] = { en.BITMAP, 20, "Contract", {
        [0] = { en.network_id, 24, "ContractNetworkId" },
        [1] = { en.undefined,  8, "ContractProvider" },
        [2] = { en.undefined, 16, "ContractTariff" },
        [3] = { en.undefined, 32, "ContractSerialNumber" },
        [4] = { en.BITMAP,  2, "ContractCustomerInfo", {
            [0] = { en.undefined,  6, "ContractCustomerProfile" },
            [1] = { en.undefined, 32, "ContractCustomerNumber" },
        }},
        [5] = { en.BITMAP,  2, "ContractPassengerInfo", {
            [0] = { en.undefined,  6, "ContractPassengerClass" },
            [1] = { en.undefined, 32, "ContractPassengerTotal" },
        }},
        [6] = { en.undefined, 6, "ContractVehiculeClassAllowed" },
        [7] = { en.undefined, 32, "ContractPaymentPointer" },
        [8] = { en.undefined, 11, "ContractPayMethod" },
        [9] = { en.undefined, 16, "ContractServices" },
        [10] = { en.amount, 16, "ContractPriceAmount" },
        [11] = { en.undefined, 16, "ContractPriceUnit" },
        [12] = { en.BITMAP, 7, "ContractRestriction", {
            [0] = { en.time, 11, "ContractStartTime" },
            [1] = { en.time, 11, "ContractEndTime" },
            [2] = { en.undefined, 8, "ContractRestrictDay" },
            [3] = { en.undefined, 8, "ContractRestrictTimeCode" },
            [4] = { en.undefined, 8, "ContractRestrictCode" },
            [5] = { en.undefined, 16, "ContractRestrictProduct" },
            [6] = { en.undefined, 16, "ContractRestrcitLocation" },
        }},
        [13] = { en.BITMAP, 9, "ContractValidityInfo", {
            [0] = { en.date, 14, "ContractStartDate" },
            [1] = { en.time, 11, "ContractStartTime" },
            [2] = { en.date, 14, "ContractEndDate" },
            [3] = { en.time, 11, "ContractEndTime" },
            [4] = { en.undefined, 8, "ContractDuration" },
            [5] = { en.date, 14, "ContractLimitDate" },
            [6] = { en.zones, 8, "ContractZones" },
            [7] = { en.undefined, 16, "ContractJourneys" },
            [8] = { en.undefined, 16, "ContractPeriodJourneys" },
        }},
        [14] = { en.BITMAP, 8, "ContractJourneyData", {
            [0] = { en.undefined, 16, "ContractOrigin" },
            [1] = { en.undefined, 16, "ContractDestination" },
            [2] = { en.undefined, 16, "ContractRouteNumbers" },
            [3] = { en.undefined, 8, "ContractRouteVariants" },
            [4] = { en.undefined, 16, "ContractRun" },
            [5] = { en.undefined, 16, "ContractVia" },
            [6] = { en.undefined, 16, "ContractDistance" },
            [7] = { en.undefined, 8, "ContractInterchange" },
        }},
        [15] = { en.BITMAP, 4, "ContractSaleData", {
            [0] = { en.date, 14, "ContractDate" },
            [1] = { en.time, 11, "ContractTime" },
            [2] = { en.undefined, 8, "ContractAgent" },
            [3] = { en.undefined, 16, "ContractDevice" },
        }},
        [16] = { en.undefined, 8, "ContractStatus" },
        [17] = { en.undefined, 16, "ContractLoyalityPoints" },
        [18] = { en.undefined, 16, "ContractAuthenticator" },
        [19] = { en.undefined, 0, "Contract"},
    }}
}

intercode_Event = {
    [0] = { en.date, 14, "EventDate" },
    [1] = { en.time, 11, "EventTime" },
    [2] = { en.BITMAP, 28, "Event", {
        [0] = { en.undefined,  8, "EventDisplayData" },
        [1] = { en.network_id, 24, "EventNetworkId" },
        [2] = { en.undefined,  8, "EventCode" },
        [3] = { en.undefined,  8, "EventResult" },
        [4] = { en.undefined,  8, "EventServiceProvider" },
        [5] = { en.undefined,  8, "EventNotOkCounter" },
        [6] = { en.undefined, 24, "EventSerialNumber" },
        [7] = { en.undefined, 16, "EventDestination" },
        [8] = { en.undefined, 16, "EventLocationId" },
        [9] = { en.undefined,  8, "EventLocationGate" },
        [10] = { en.undefined, 16, "EventDevice" },
        [11] = { en.number, 16, "EventRouteNumber" },
        [12] = { en.undefined,  8, "EventRouteVariant" },
        [13] = { en.undefined, 16, "EventJourneyRun" },
        [14] = { en.undefined, 16, "EventVehiculeId" },
        [15] = { en.undefined,  8, "EventVehiculeClass" },
        [16] = { en.undefined,  5, "EventLocationType" },
        [17] = { en.undefined,240, "EventEmployee" },
        [18] = { en.undefined, 16, "EventLocationReference" },
        [19] = { en.undefined,  8, "EventJourneyInterchanges" },
        [20] = { en.undefined, 16, "EventPeriodJourneys" },
        [21] = { en.undefined, 16, "EventTotalJourneys" },
        [22] = { en.undefined, 16, "EventJourneyDistance" },
        [23] = { en.amount, 16, "EventPriceAmount" },
        [24] = { en.undefined, 16, "EventPriceUnit" },
        [25] = { en.undefined,  5, "EventContractPointer" },
        [26] = { en.undefined, 16, "EventAuthenticator" },
        [27] = { en.undefined,  5, "EventBitmapExtra" },
    }}
}

function intercode_map_contracts(contract_mappings)
    if #intercode_Contract_types ~= #intercode_Contract_pointers then
        cp.log.warning( "Cannot map contracts: #intercode_Contract_types != #intercode_Contract_pointers")
        return
    end
    for i, pointer in ipairs(intercode_Contract_pointers) do
        local contract_type = intercode_Contract_types[i]
        local contract_type_str = string.format('%02Xh', contract_type)

        if contract_mappings[contract_type_str] == nil then
            -- Support for more contract types can be added by defining contract_mappings["XXh"]
            cp.log.info( "Cannot map contract "..pointer..": contract type "..contract_type_str.." not implemented")
        else
            local contract_mapping = contract_mappings[contract_type_str]
            cp.log.info( "Map contract "..pointer..": contract type "..contract_type_str)

            -- Determine the record associated to this contract pointer
            -- TODO : adapt to other card type (the following mapping is for CD97 structure 2)
            local file_id
            local rec_id
            if pointer >= 5 then
                file_id = 2030
                rec_id = pointer - 4
            else
                file_id = 2020
                rec_id = pointer
            end

            local condition = {
                file = { label = "Contracts", id = file_id },
                record = { label = "record", id = rec_id },
            }

            en.map(CARD, condition, contract_mapping)
        end
    end
end

en.map(CARD, "Environment", intercode_Env, intercode_Holder)
en.map(CARD, "Contract list", intercode_BestContracts)
intercode_map_contracts(intercode_Contract)
en.map(CARD, "Event logs", intercode_Event)
en.map(CARD, "Special events", intercode_Event)
card_num(CARD)

end
