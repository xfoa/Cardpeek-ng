-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id vitale-2
-- @title Vitale 2
-- @description Inspect French Vitale 2 health card files
-- @version 1.0.0
--
-- Copyright 2009-2013 by 'L1L1'
-- Licensed under GPL-3.0-or-later. See the project NOTICE.md.

local cp = require('cardpeek')
local util = require('lib.util')
local apdu = require('lib.apdu')
local tlv = require('lib.tlv')

local function ascii_date(node, data)
  local value = util.format(data, '%P')
  local time = os.time({ year = tonumber(value:sub(1, 4)), month = tonumber(value:sub(5, 6)), day = tonumber(value:sub(7, 8)) })
  node:set('value', data)
  node:set('alternative', os.date('%x', time))
  return true
end

local VITALE_IDO = {
  ['65'] = { 'Bénéficiaire' }, ['65/90'] = { 'Nationalité', tlv.parsers.printable },
  ['65/93'] = { 'Numéro de sécurité sociale', tlv.parsers.printable },
  ['65/80'] = { 'Nom', tlv.parsers.printable }, ['65/81'] = { 'Prénom', tlv.parsers.printable },
  ['65/82'] = { 'Date de naissance', ascii_date }, ['66'] = { 'Carte vitale' },
  ['66/80'] = { 'Date de début de validité', ascii_date }, ['7F21'] = { 'Certificat' },
  ['5F37'] = { "Signature de l'AC" }, ['5F38'] = { 'Résidu de la clé publique' },
}

local AID_VITALE = '#D250000002564954414C45'
local AID_VITALE_MF = '#D2500000024D465F564954414C45'

local function read_binary()
  local data = util.bytes(8)
  local offset = 0
  repeat
    local response = apdu.read_binary(offset, 0)
    data = data .. response.data
    offset = offset + #response.data
    if response.status ~= 0x9000 then return response, data end
  until #response.data < 256
  return { status = 0x9000 }, data
end

local function create_card_map()
  local response = apdu.select(AID_VITALE)
  if response.status ~= 0x9000 then return nil end
  response = apdu.select('.2001')
  if response.status ~= 0x9000 then return nil end
  local status, data = read_binary()
  if status.status ~= 0x9000 then return nil end

  local map = {}
  local tag, value, tail = cp.asn1.split(data)
  if tag == nil then return nil end
  local _, applications, descriptors = cp.asn1.split(value)
  while applications do
    local application_tag, application
    application_tag, application, applications = cp.asn1.split(applications)
    if application_tag == 0x82 and #application >= 4 then
      local entry = util.sub(application, 0, 1):to_hex()
      map[entry] = { aid = '#' .. util.sub(application, 4):to_hex(), files = {} }
    end
  end
  while descriptors do
    local descriptor_tag, descriptor
    descriptor_tag, descriptor, descriptors = cp.asn1.split(descriptors)
    if descriptor_tag == 0x80 and #descriptor >= 12 then
      local entry = util.sub(descriptor, 8, 9):to_hex()
      if map[entry] then
        table.insert(map[entry].files, {
          name = util.format(util.sub(descriptor, 0, 7), '%P'),
          id = '.' .. util.sub(descriptor, 10, 11):to_hex(),
        })
      end
    end
  end
  for _, app in pairs(map) do
    if app.aid == AID_VITALE_MF then
      table.insert(app.files, { name = 'DIR', id = '.2F00' })
      table.insert(app.files, { name = 'PAN', id = '.2F02' })
    elseif app.aid == AID_VITALE then
      table.insert(app.files, { name = 'POINTERS', id = '.2001' })
    end
  end
  return map
end

local root = apdu.start('VITALE 2')
local map = create_card_map()
if map then
  for _, application in pairs(map) do
    local response = apdu.select(application.aid)
    local app = util.node(root, 'application', 'Application', nil, nil, application.aid)
    local header = util.node(app, 'header', 'answer to select', response.data)
    tlv.parse(header, response.data)
    if response.status == 0x9000 then
      for _, file in ipairs(application.files) do
        response = apdu.select(file.id)
        local file_node = util.node(app, 'file', file.name, nil, nil, file.id)
        local file_header = util.node(file_node, 'header', 'answer to select', response.data)
        tlv.parse(file_header, response.data)
        if response.status == 0x9000 then
          local status, data = read_binary()
          local content = util.node(file_node, 'body', 'content', data)
          if status.status == 0x9000 and #data > 0 and data[1] ~= 0 and not (#data > 1 and data[1] == 4 and data[2] == 0) then
            content:set('value', nil)
            tlv.parse(content, data, VITALE_IDO)
          elseif status.status ~= 0x9000 then
            content:set('alternative', string.format('data not accessible (code %04X)', status.status))
          end
        end
      end
    end
  end
else
  util.node(root, 'item', 'Vitale application not found')
end
