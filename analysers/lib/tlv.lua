local cp = require('cardpeek')
local util = require('lib.util')

local M = {}
local country = require('lib.country_codes')
local currency = require('lib.currency_codes')

local function set_number(node, data)
  node:set('value', data)
  node:set('alternative', string.format('%.0f', util.number(data)))
end

local function set_printable(node, data)
  node:set('value', data)
  if #data == 0 then return false end
  if util.printable(data) then
    node:set('alternative', util.format(data, '%P'))
  else
    node:set('alternative', util.format(data, '%P (%D)'))
  end
  return true
end

local function set_date(node, data)
  local text = data:to_hex()
  local year = tonumber(text:sub(1, 2)) + 1900
  if year < 1980 then year = year + 100 end
  local time = os.time({ year = year, month = tonumber(text:sub(3, 4)), day = tonumber(text:sub(5, 6)) })
  node:set('value', data)
  node:set('alternative', os.date('%x', time))
end

local function set_country(node, data)
  node:set('value', data)
  node:set('alternative', country.name(tonumber(data:to_hex())))
end

local function set_currency(node, data)
  node:set('value', data)
  node:set('alternative', currency.name(tonumber(data:to_hex())))
end

local function set_oid(node, data)
  if #data == 0 then return false end
  local output = { '{ ' .. math.floor(data[1] / 40) .. ' ' .. (data[1] % 40) }
  local item = 0
  for value in data:iter() do
    item = item * 128 + (value & 0x7F)
    if value < 0x80 then
      table.insert(output, tostring(item))
      item = 0
    end
  end
  table.insert(output, ' }')
  node:set('value', data)
  node:set('alternative', table.concat(output, ' '))
  return true
end

M.parsers = {
  number = set_number,
  printable = set_printable,
  date = set_date,
  country = set_country,
  currency = set_currency,
  oid = set_oid,
}

local ISO = {
  ['2'] = { 'Integer' }, ['3'] = { 'Bit String' }, ['4'] = { 'Octet String' },
  ['5'] = { 'Null' }, ['6'] = { 'Object identifier', set_oid },
  ['13'] = { 'Printable String', set_printable }, ['14'] = { 'T61 String' },
  ['16'] = { 'IA5 String' }, ['17'] = { 'UTC Time', set_printable },
  ['30'] = { 'Sequence' }, ['31'] = { 'Set' }, ['41'] = { 'Country authority' },
  ['42'] = { 'Issuer authority' }, ['43'] = { 'Card service data' },
  ['44'] = { 'Initial access data' }, ['45'] = { "Card issuer's data" },
  ['46'] = { 'Pre-issuing data' }, ['47'] = { 'Card capabilities' },
  ['48'] = { 'Status information' }, ['4F'] = { 'Application Identifier (AID)' },
  ['50'] = { 'Application Label', set_printable }, ['51'] = { 'Path' },
  ['52'] = { 'Command to perform' }, ['53'] = { 'Discretionary data' },
  ['56'] = { 'Track 1 Equivalent Data' }, ['57'] = { 'Track 2 Equivalent Data' },
  ['58'] = { 'Track 3 Equivalent Data' }, ['59'] = { 'Card expiration date' },
  ['5A'] = { 'Application PAN' }, ['5B'] = { 'Name', set_printable },
  ['5C'] = { 'Tag list' }, ['5D'] = { 'Tag length list' }, ['5E'] = { 'Log-in data' },
  ['5F20'] = { 'Cardholder Name', set_printable }, ['5F21'] = { 'Track 1 Data' },
  ['5F22'] = { 'Track 2 Data' }, ['5F23'] = { 'Track 3 Data' },
  ['5F24'] = { 'Application Expiration Date', set_date }, ['5F25'] = { 'Application Effective Date', set_date },
  ['5F26'] = { 'Card Effective Date', set_date }, ['5F27'] = { 'Interchange control' },
  ['5F28'] = { 'Country Code', set_country }, ['5F29'] = { 'Interchange profile' },
  ['5F2A'] = { 'Currency code', set_currency }, ['5F2B'] = { 'Date of birth' },
  ['5F2C'] = { 'Cardholder nationality' }, ['5F2D'] = { 'Language Preference', set_printable },
  ['5F2E'] = { 'Cardholder biometric data' }, ['5F2F'] = { 'PIN usage policy' },
  ['5F30'] = { 'Service Code' }, ['5F32'] = { 'Transaction counter' },
  ['5F34'] = { 'Application PAN Sequence Number' }, ['5F50'] = { 'Issuer URL' },
  ['62'] = { 'File Control Parameters (FCP) Template' },
  ['62/80'] = { 'Data size excluding structural information', set_number },
  ['62/81'] = { 'Data size including structural information', set_number },
  ['62/82'] = { 'File descriptor' }, ['62/83'] = { 'File identifier' },
  ['62/84'] = { 'Dedicated File (DF) Name', set_printable },
  ['62/85'] = { 'Proprietary information' }, ['62/86'] = { 'Security attributes' },
  ['62/87'] = { 'EF containing FCI extension' }, ['63'] = { 'wrapper' },
  ['64'] = { 'File Management Data (FMD) Template' }, ['6F'] = { 'File Control Information (FCI) Template' },
  ['6F/80'] = { 'Data size excluding structural information', set_number },
  ['6F/81'] = { 'Data size including structural information', set_number },
  ['6F/82'] = { 'File descriptor' }, ['6F/83'] = { 'File identifier' },
  ['6F/84'] = { 'Dedicated File (DF) Name', set_printable },
  ['6F/85'] = { 'Proprietary information' }, ['6F/86'] = { 'Security attributes' },
  ['6F/87'] = { 'EF containing FCI extension' }, ['72'] = { 'Issuer Script Template 2' },
  ['73'] = { 'Discretionary DOs' }, ['A5'] = { 'FCI Proprietary Template' },
}

local TYPES = { 'TLV (Universal)', 'TLV (Application-specific)', 'TLV (Context-specific)', 'TLV (Private)' }

local function info(tag, reference, parent)
  local key = string.format('%X', tag)
  local nested = string.format('%X/%s', parent, key)
  local item = reference[nested] or reference[key] or ISO[nested] or ISO[key]
  if item then return item[1], item[2] end
  return nil, nil
end

local function compound(tag)
  local first = tag
  while first > 255 do first = math.floor(first / 256) end
  return (first & 0x20) ~= 0
end

local parse

local function one(parent_node, tag, value, reference, parent)
  local name, parser = info(tag, reference, parent)
  if not name then name = TYPES[((tag >> 6) & 3) + 1] end
  local node = util.node(parent_node, 'item', name, nil, nil, string.format('%X', tag))
  if compound(tag) then
    if not parse(node, value, reference, tag) then
      node:remove()
      return false
    end
  elseif parser then
    parser(node, value)
  else
    node:set('value', value)
  end
  return node
end

parse = function(parent_node, data, reference, parent)
  reference = reference or {}
  local last = false
  while data ~= nil do
    local tag, value, tail = cp.asn1.split(data)
    if tag == nil or tag == 0 then
      return util.node(parent_node, 'card', 'Unparsed ASN1 data', data, '(error)')
    end
    last = one(parent_node, tag, value, reference, parent or 0)
    if last == false then return false end
    data = tail
  end
  return last
end

function M.parse(parent_node, data, reference)
  return parse(parent_node, data, reference or {}, 0)
end

function M.one(parent_node, tag, value, reference)
  return one(parent_node, tag, value, reference or {}, 0)
end

function M.info(tag, reference, parent)
  return info(tag, reference or {}, parent or 0)
end

function M.tag_type(tag)
  return TYPES[((tag >> 6) & 3) + 1]
end

return M
