-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id thai-eid
-- @title Thai eID
-- @description Inspect Thai national electronic identity card data
-- @version 1.0.0
--
-- By David Huang <khym@azeotrope.org>
-- Based on https://github.com/chakphanu/ThaiNationalIDCard
-- Licensed under GPL-3.0-or-later. See the project NOTICE.md.

local cp = require('cardpeek')
local util = require('lib.util')
local apdu = require('lib.apdu')

local function text(node)
  local data = node:get('value')
  local value = cp.encoding.decode('TIS-620', data):gsub(' +$', '')
  node:set('alternative', value)
  return value
end

local function split_hash(node, labels)
  local value = text(node)
  local pattern = string.rep('([^#]*)', #labels, '#')
  for index, part in ipairs({ value:match(pattern) }) do
    if labels[index] then util.node(node, 'item', labels[index], part) end
  end
end

local function name(node)
  split_hash(node, { 'Prefix', 'First', 'Middle', 'Last' })
end

local function address(node)
  split_hash(node, { 'House Number', 'Village Number (Mu Ban)', 'Lane (Trok/Soi)',
    'Road (Thanon)', nil, 'Tambon/Khwaeng', 'Amphur/Khet', 'Province' })
end

local function citizen_id(node)
  local a, b, c, d, e = text(node):match('(.)(....)(.....)(..)(.)')
  node:set('alternative', string.format('%s-%s-%s-%s-%s', a, b, c, d, e))
end

local function serial(node)
  local a, b, c = text(node):match('(....)(..)(.*)')
  node:set('alternative', string.format('%s-%s-%s', a, b, c))
end

local function date(node)
  local value = text(node)
  if value == '99999999' then
    node:set('alternative', 'Lifelong')
    return
  end
  local year, month, day = value:match('(....)(..)(..)')
  node:set('alternative', string.format('%04d-%02d-%02d', tonumber(year) - 543, tonumber(month), tonumber(day)))
end

local function sex(node)
  local value = util.get(node:get('value'), 0)
  local decoded = value == 0x31 and 'Male' or value == 0x32 and 'Female' or string.format('Unknown %c', value)
  node:set('alternative', decoded)
end

local function photo(node)
  node:set('mime_type', 'image/jpeg')
end

local ELEMENTS = {
  { 'Citizen ID', 4, 13, citizen_id }, { 'Thai Name', 17, 100, name },
  { 'Romanized Name', 117, 100, name }, { 'Date of Birth', 217, 8, date },
  { 'Sex', 225, 1, sex }, { 'Address', 5497, 160, address },
  { 'Date of Issue', 359, 8, date }, { 'Date of Expiry', 367, 8, date },
  { 'Issuer', 246, 100, text }, { 'Card Number', 5657, 14, serial },
  { 'Photo', 379, 5118, photo },
}

local function read_data()
  local response = apdu.select('#A000000054480001')
  if response.status ~= 0x9000 then return nil, response.status end
  local data = util.bytes(8)
  local remaining = 5950
  for offset = 0, 5949, 255 do
    local length = math.min(255, remaining)
    response = util.transmit(util.bytes(8, 0x80, 0xB0, (offset >> 8) & 0x7F, offset & 0xFF, 0x02, 0x00, length))
    if response.status ~= 0x9000 then return nil, response.status end
    data = data .. response.data
    remaining = remaining - #response.data
  end
  return data, 0x9000
end

local root = apdu.start('Thai eID')
local data, status = read_data()
if data then
  for _, element in ipairs(ELEMENTS) do
    local value = util.sub(data, element[2], element[2] + element[3] - 1)
    if value then
      local node = util.node(root, 'item', element[1], value)
      element[4](node)
    end
  end
else
  util.node(root, 'item', 'Card data not accessible', nil, string.format('%04X', status))
end
