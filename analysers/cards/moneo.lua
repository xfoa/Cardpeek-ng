-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id moneo
-- @title Moneo
-- @description Inspect French Moneo stored-value card records
-- @version 1.0.0
--
-- Copyright 2009-2013 by 'L1L1'
-- April 2013 contributions by Darius Matboo.
-- Licensed under GPL-3.0-or-later. See the project NOTICE.md.

local util = require('shared.lib.util')
local apdu = require('shared.lib.apdu')
local tlv = require('shared.lib.tlv')

local function bcd(data, index)
  local value = util.get(data, index)
  if value == nil then error('truncated Moneo BCD field') end
  return tonumber(string.format('%x', value))
end

local function amount(data)
  return string.format('%d,%02d Euros', bcd(data, 0) * 100 + bcd(data, 1), bcd(data, 2))
end

local function date(data)
  return string.format('%02d/%02d/%d', bcd(data, 2), bcd(data, 1), 2000 + bcd(data, 0))
end

local function date_time(data)
  return string.format('%02d/%02d/%d %02d:%02d:%02d', bcd(data, 3), bcd(data, 2),
    bcd(data, 0) * 100 + bcd(data, 1), bcd(data, 4), bcd(data, 5), bcd(data, 6))
end

local function identifiers(node, data)
  util.node(node, 'item', 'PAN', util.sub(data, 0, 9), util.sub(data, 0, 9):to_hex())
  util.node(node, 'item', "Date d'expiration", util.sub(data, 10, 11),
    string.format('%d/%d', bcd(data, 11), bcd(data, 10) + 2000))
  util.node(node, 'item', "Date d'activation", util.sub(data, 12, 14), date(util.sub(data, 12, 14)))
  util.node(node, 'item', 'Code pays', util.sub(data, 15, 16))
  util.node(node, 'item', 'Code monnaie', util.sub(data, 17, 19), util.format(util.sub(data, 17, 19), '%C'))
end

local function reload_journal(node, data)
  util.node(node, 'item', 'Compteur de rechargements', util.sub(data, 1, 2), util.number(util.sub(data, 1, 2)))
  util.node(node, 'item', 'Montant de recharge', util.sub(data, 4, 6), amount(util.sub(data, 4, 6)))
  util.node(node, 'item', 'Reste', util.sub(data, 7, 9), amount(util.sub(data, 7, 9)))
  util.node(node, 'item', 'Terminal', util.sub(data, 13, 20))
  util.node(node, 'item', 'Date', util.sub(data, 24, 30), date_time(util.sub(data, 24, 30)))
end

local function purchase_journal(node, data)
  util.node(node, 'item', "Compteur d'achats", util.sub(data, 1, 2), util.number(util.sub(data, 1, 2)))
  util.node(node, 'item', 'Montant de la transaction', util.sub(data, 5, 7), amount(util.sub(data, 5, 7)))
  util.node(node, 'item', 'Terminal', util.sub(data, 8, 17))
  util.node(node, 'item', 'Date', util.sub(data, 29, 35), date_time(util.sub(data, 29, 35)))
  util.node(node, 'item', 'Reste', util.sub(data, 26, 28), amount(util.sub(data, 26, 28)))
end

local function amounts(node, data)
  util.node(node, 'item', 'Credit actuel', util.sub(data, 0, 2), amount(util.sub(data, 0, 2)))
  util.node(node, 'item', 'Credit maximum', util.sub(data, 3, 5), amount(util.sub(data, 3, 5)))
  util.node(node, 'item', 'Montant maximum de transaction', util.sub(data, 6, 8), amount(util.sub(data, 6, 8)))
end

local function sequence_number(node, data)
  node:set('alternative', string.format('%.0f', util.number(data)))
end

local FILES = {
  { 'Rechargement rapide', 0x08 },
  { 'Numero de sequence de rechargement rapide', 0x0A, sequence_number },
  { 'ICP', 0x0C }, { 'Identifiants', 0x17, identifiers },
  { 'Montants', 0x18, amounts }, { 'Type de porte-monnaie', 0x19 },
  { 'Numero de sequence de rechargement', 0x1A, sequence_number },
  { "Numero de sequence d'achat", 0x1B, sequence_number },
  { 'Journal des rechargements', 0x1C, reload_journal },
  { 'Journal des achats', 0x1D, purchase_journal },
}

local root = apdu.start('MONEO')
local response = apdu.select('#A00000006900', nil, 0)
if response.status == 0x9000 then
  local app = util.node(root, 'application', 'application', nil, nil, 'A00000006900')
  tlv.parse(app, response.data)
  for _, file in ipairs(FILES) do
    local file_node = util.node(app, 'file', file[1], nil, nil, string.format('%02X', file[2]))
    for record_number = 1, 255 do
      response = apdu.read_record(file[2], record_number)
      if response.status ~= 0x9000 or #response.data == 0 then break end
      local record = util.node(file_node, 'record', 'record', response.data, nil, record_number)
      if file[3] then file[3](record, response.data) end
    end
  end
else
  util.node(root, 'item', 'Moneo application not found', nil, string.format('%04X', response.status))
end
