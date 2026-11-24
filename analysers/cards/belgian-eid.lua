-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id belgian-eid
-- @title Belgian eID
-- @description Inspect Belgian electronic identity card files
-- @version 1.0.0
--
-- Copyright 2009-2013 by 'L1L1'
-- Licensed under GPL-3.0-or-later. See the project NOTICE.md.

local cp = require('cardpeek')
local util = require('shared.lib.util')
local apdu = require('shared.lib.apdu')
local tlv = require('cardpeek').tlv

local printable = tlv.parsers.printable

local EID_IDO = {
  ['0'] = { 'File structure version' }, ['1'] = { 'Card number', printable },
  ['2'] = { 'Chip number' }, ['3'] = { 'Card validity start date', printable },
  ['4'] = { 'Card validity end date', printable }, ['5'] = { 'Card delivery municipality', printable },
  ['6'] = { 'National number', printable }, ['7'] = { 'Name', printable },
  ['8'] = { '2 first given names', printable }, ['9'] = { 'First letter of third given name', printable },
  ['A'] = { 'Nationality', printable }, ['B'] = { 'Birth location', printable },
  ['C'] = { 'Birth date', printable }, ['D'] = { 'Sex', printable },
  ['E'] = { 'Noble condition', printable }, ['F'] = { 'Document type', printable },
  ['10'] = { 'Special status', printable }, ['11'] = { 'Hash of photo' },
}

local ADDRESS_IDO = {
  ['0'] = { 'File structure version' }, ['1'] = { 'Street and number', printable },
  ['2'] = { 'ZIP code', printable }, ['3'] = { 'Municipality', printable },
}

local function process_photo(node)
  node:set('mime_type', 'image/jpeg')
end

local function process_tlv(node)
  tlv.parse(node, node:get('value'))
end

local function process_id(node)
  tlv.parse(node, node:get('value'), EID_IDO)
end

local function process_address(node)
  tlv.parse(node, node:get('value'), ADDRESS_IDO)
end

local structure = {
  { 'folder', 'MF', '.3F00', {
    { 'file', 'EF_DIR', '.2F00', process_tlv },
    { 'folder', 'DF_BELPIC', '.DF00', {
      { 'file', 'EF_ODF', '.5031', process_tlv },
      { 'file', 'EF_TokenInfo', '.5032', process_tlv },
      { 'file', 'EF_AODF', '.5034', process_tlv },
      { 'file', 'EF_PrKDF', '.5035', process_tlv },
      { 'file', 'EF_CDF', '.5037', process_tlv },
      { 'file', 'EF_Cert#2', '.5038', process_tlv },
      { 'file', 'EF_Cert#3', '.5039', process_tlv },
      { 'file', 'EF_Cert#4', '.503A', process_tlv },
      { 'file', 'EF_Cert#6', '.503B', process_tlv },
      { 'file', 'EF_Cert#8', '.503C', process_tlv },
    } },
    { 'folder', 'DF_ID', '.DF01', {
      { 'file', 'EF_ID#RN', '.4031', process_id },
      { 'file', 'EF_SGN#RN', '.4032' },
      { 'file', 'EF_ID#Address', '.4033', process_address },
      { 'file', 'EF_SGN#Address', '.4034' },
      { 'file', 'EF_ID#Photo', '.4035', process_photo },
      { 'file', 'EF_PuK#7', '.4038' },
      { 'file', 'EF_Preferences', '.4039' },
    } },
  } },
}

local function restore_path(path)
  for _, file_id in ipairs(path) do apdu.select(file_id, 0x0C) end
end

local function load_files(parent, entries, path)
  path = path or {}
  for _, entry in ipairs(entries) do
    local response = apdu.select(entry[3], 0x0C)
    if response.status == 0x9000 then
      local node = util.node(parent, entry[1], entry[2], nil, nil, entry[3])
      if type(entry[4]) == 'table' then
        table.insert(path, entry[3])
        load_files(node, entry[4], path)
        table.remove(path)
        restore_path(path)
      else
        local position = 0
        local data = cp.bytes.pack(8)
        repeat
          response = apdu.read_binary(position, 0)
          data = data .. response.data
          position = position + #response.data
        until response.status ~= 0x9000 or #response.data < 256
        if #data > 0 then
          node:set('value', data)
          if type(entry[4]) == 'function' then entry[4](node) end
        else
          node:set('alternative', string.format('No content (code %04X)', response.status))
        end
      end
    end
  end
end

local root = apdu.start('Belgian eID')
load_files(root, structure)
