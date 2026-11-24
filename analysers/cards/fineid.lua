-- @id fineid
-- @title Finnish eID
-- @description Inspect Finnish Henkilokortti FINEID metadata and public certificates
-- @version 1.0.0
-- @capabilities live, replay

local cp = require('cardpeek')
local util = require('shared.lib.util')
local apdu = require('shared.lib.apdu')
local tlv = require('cardpeek').tlv

local FINEID_AID = 'A000000063504B43532D3135'
local certificate_count = 0

local function utf8(data)
  local ok, value = pcall(cp.encoding.decode, 'UTF-8', data)
  if ok then return value end
  return cp.bytes.format(data, '%P')
end

local function text_parser(node, data)
  node:set('value', data)
  node:set('alternative', utf8(data))
end

local function oid(data)
  if #data == 0 then return '' end
  local numbers = {}
  local item = 0
  for value in data:iter() do
    item = item * 128 + (value & 0x7F)
    if value < 0x80 then
      table.insert(numbers, item)
      item = 0
    end
  end
  if #numbers > 0 then
    local first = numbers[1]
    local high = math.min(2, math.floor(first / 40))
    numbers[1] = high
    table.insert(numbers, 2, first - high * 40)
  end
  return table.concat(numbers, '.')
end

local function oid_parser(node, data)
  node:set('value', data)
  node:set('alternative', oid(data))
end

local DER = {
  ['2'] = { 'Integer', tlv.parsers.number },
  ['3'] = { 'Bit String' },
  ['4'] = { 'Octet String' },
  ['6'] = { 'Object Identifier', oid_parser },
  ['C'] = { 'UTF8 String', text_parser },
  ['13'] = { 'Printable String', text_parser },
  ['16'] = { 'IA5 String', text_parser },
  ['17'] = { 'UTC Time', text_parser },
  ['18'] = { 'Generalized Time', text_parser },
  ['30'] = { 'Sequence' },
  ['31'] = { 'Set' },
  ['A0'] = { 'Attributes [0]' },
  ['A1'] = { 'Type attributes [1]' },
  ['A2'] = { 'Supported algorithms [2]' },
}

local DIR = {
  ['61'] = { 'Application template' },
  ['4F'] = { 'Application identifier' },
  ['50'] = { 'Application label', text_parser },
  ['51'] = { 'Application path' },
  ['73'] = { 'Application discretionary data' },
}

local ATR_INFO = {
  ['47'] = { 'Card capabilities' },
  ['7F66'] = { 'Extended length information' },
}

local function select_path(path)
  local encoded = path
  local control = 0
  if #path > 4 then
    if path:sub(1, 4) == '3F00' then
      encoded = path:sub(5)
      control = 8
    else
      control = 9
    end
  end
  local data = cp.bytes.from_hex(encoded)
  return util.transmit(cp.bytes.pack(8, 0, 0xA4, control, 0x0C, #data, data))
end

local function read_chunk(offset, length)
  local response = apdu.read_binary(offset, length or 0)
  if response.status >= 0x6C00 and response.status <= 0x6CFF and #response.data < 256 then
    response = apdu.read_binary(offset, response.status & 0xFF)
  end
  local data = cp.bytes.pack(8)
  local responses = 0
  repeat
    data = data .. response.data
    if response.status < 0x6100 or response.status > 0x61FF then break end
    response = util.transmit(cp.bytes.pack(8, 0, 0xC0, 0, 0, response.status & 0xFF))
    responses = responses + 1
  until responses >= 256
  return data, response.status
end

local function der_size(data)
  if #data < 2 or data[1] ~= 0x30 then return nil end
  local first = data[2]
  if first < 0x80 then return first + 2 end
  local count = first & 0x7F
  if count == 0 or count > 2 then return nil end
  if #data < count + 2 then return 0 end
  local length = 0
  for index = 1, count do length = length * 256 + data[index + 2] end
  return count + 2 + length
end

local function read_file(parent, label, path, decoder)
  local node = util.node(parent, 'file', label, nil, nil, path)
  local response = select_path(path)
  if response.status ~= 0x9000 then
    node:set('alternative', string.format('Selection failed (status %04X)', response.status))
    return nil, response.status
  end
  local data = cp.bytes.pack(8)
  local expected
  for _ = 1, 520 do
    local remaining = expected and expected - #data
    local length = remaining and remaining < 256 and remaining or 0
    local chunk, status = read_chunk(#data, length)
    data = data .. chunk
    expected = der_size(data) or expected
    if expected and #data >= expected then break end
    if status ~= 0x9000 then
      if status == 0x6B00 and #data > 0 then break end
      node:set('alternative', string.format('Read failed (status %04X)', status))
      return nil, status
    end
    if status == 0x6282 or (not expected and #chunk < 256) then break end
  end
  node:set('value', data)
  if decoder then decoder(node, data) end
  return data, 0x9000
end

local function serial_text(data)
  if cp.bytes.printable(data) then return utf8(data) end
  local encoded = data:to_hex()
  local digits = tonumber(encoded:sub(1, 2))
  if digits and digits == #encoded - 2 then return encoded:sub(3) end
  return encoded
end

local function decode_cia(node, data)
  local tag, content = cp.asn1.split(data)
  if tag ~= 0x30 then
    util.node(node, 'item', 'Invalid CIAInfo', data, 'Expected a DER sequence')
    return
  end
  while content do
    local field, value
    field, value, content = cp.asn1.split(content)
    if field == 0x02 then
      util.node(node, 'item', 'CIAInfo version', value, string.format('%.0f', cp.bytes.number(value)))
    elseif field == 0x04 then
      util.node(node, 'item', 'Card serial number', value, serial_text(value))
    elseif field == 0x0C then
      util.node(node, 'item', 'Manufacturer', value, utf8(value))
    elseif field == 0x80 then
      util.node(node, 'item', 'Application label', value, utf8(value))
    elseif field == 0x03 then
      util.node(node, 'item', 'Card flags', value)
    elseif field == 0xA2 then
      local algorithms = util.node(node, 'item', 'Supported algorithms', value)
      tlv.parse(algorithms, value, DER)
    elseif field == 0x13 then
      util.node(node, 'item', 'Preferred language', value, utf8(value))
    end
  end
end

local function find_label(data)
  if not data then return nil end
  local tag, value, tail = cp.asn1.split(data)
  if not tag then return nil end
  if tag == 0x0C then return utf8(value) end
  if tag & 0x20 ~= 0 then return find_label(value) end
  return find_label(tail)
end

local function find_path(data)
  local found
  local function visit(encoded)
    if not encoded then return end
    local tag, value, tail = cp.asn1.split(encoded)
    if not tag then return end
    if tag == 0x04 and #value >= 2 then found = value:to_hex() end
    if tag & 0x20 ~= 0 then visit(value) end
    visit(tail)
  end
  visit(data)
  return found
end

local NAME_OIDS = {
  ['2.5.4.3'] = 'CN',
  ['2.5.4.4'] = 'surname',
  ['2.5.4.5'] = 'serialNumber',
  ['2.5.4.6'] = 'C',
  ['2.5.4.7'] = 'L',
  ['2.5.4.8'] = 'ST',
  ['2.5.4.9'] = 'street',
  ['2.5.4.10'] = 'O',
  ['2.5.4.11'] = 'OU',
  ['2.5.4.12'] = 'title',
  ['2.5.4.42'] = 'givenName',
  ['1.2.840.113549.1.9.1'] = 'emailAddress',
}

local ALGORITHM_OIDS = {
  ['1.2.840.113549.1.1.1'] = 'RSA',
  ['1.2.840.113549.1.1.10'] = 'RSA-PSS',
  ['1.2.840.113549.1.1.11'] = 'SHA-256 with RSA',
  ['1.2.840.113549.1.1.12'] = 'SHA-384 with RSA',
  ['1.2.840.113549.1.1.13'] = 'SHA-512 with RSA',
  ['1.2.840.10045.2.1'] = 'EC public key',
  ['1.2.840.10045.4.3.2'] = 'SHA-256 with ECDSA',
  ['1.2.840.10045.4.3.3'] = 'SHA-384 with ECDSA',
  ['1.2.840.10045.4.3.4'] = 'SHA-512 with ECDSA',
}

local function decode_name(data)
  if not data then return '' end
  local names = {}
  local sets = data
  while sets do
    local set_tag, set_value
    set_tag, set_value, sets = cp.asn1.split(sets)
    if set_tag ~= 0x31 then break end
    local sequence_tag, sequence = cp.asn1.split(set_value)
    if sequence_tag ~= 0x30 then break end
    local oid_tag, encoded_oid, string_data = cp.asn1.split(sequence)
    if oid_tag ~= 0x06 then break end
    local string_tag, string_value = cp.asn1.split(string_data)
    local identifier = oid(encoded_oid)
    if string_tag then
      table.insert(names, (NAME_OIDS[identifier] or identifier) .. '=' .. utf8(string_value))
    end
  end
  return table.concat(names, ', ')
end

local function decode_algorithm(data)
  if not data then return '' end
  local oid_tag, value = cp.asn1.split(data)
  if oid_tag ~= 0x06 then return '' end
  local identifier = oid(value)
  return ALGORITHM_OIDS[identifier] or identifier
end

local function decode_x509(node, data)
  node:set('mime_type', 'application/pkix-cert')
  local tag, certificate = cp.asn1.split(data)
  if tag ~= 0x30 then
    util.node(node, 'item', 'Invalid certificate', nil, 'Expected a DER sequence')
    return
  end
  local tbs_tag, tbs = cp.asn1.split(certificate)
  if tbs_tag ~= 0x30 then
    util.node(node, 'item', 'Invalid certificate', nil, 'Missing TBSCertificate')
    return
  end
  local fields = {}
  while tbs do
    local field, value
    field, value, tbs = cp.asn1.split(tbs)
    table.insert(fields, { tag = field, value = value })
  end
  local index = 1
  if fields[index] and fields[index].tag == 0xA0 then
    local _, version = cp.asn1.split(fields[index].value)
    util.node(node, 'item', 'X.509 version', fields[index].value, string.format('v%d', cp.bytes.number(version) + 1))
    index = index + 1
  end
  if fields[index] then
    util.node(node, 'item', 'Certificate serial number', fields[index].value, fields[index].value:to_hex())
  end
  if fields[index + 1] then
    util.node(node, 'item', 'Signature algorithm', fields[index + 1].value, decode_algorithm(fields[index + 1].value))
  end
  if fields[index + 2] then
    util.node(node, 'item', 'Issuer', fields[index + 2].value, decode_name(fields[index + 2].value))
  end
  if fields[index + 3] then
    local before_tag, before, after = cp.asn1.split(fields[index + 3].value)
    local after_tag, after_value = cp.asn1.split(after)
    util.node(node, 'item', 'Not before', before, (before_tag == 0x17 or before_tag == 0x18) and utf8(before) or nil)
    util.node(node, 'item', 'Not after', after_value, (after_tag == 0x17 or after_tag == 0x18) and utf8(after_value) or nil)
  end
  if fields[index + 4] then
    util.node(node, 'item', 'Subject', fields[index + 4].value, decode_name(fields[index + 4].value))
  end
  if fields[index + 5] then
    local _, algorithm = cp.asn1.split(fields[index + 5].value)
    util.node(node, 'item', 'Public key algorithm', fields[index + 5].value, decode_algorithm(algorithm))
  end
  certificate_count = certificate_count + 1
end

local function decode_certificate_directory(node, data)
  local tag, entries = cp.asn1.split(data)
  if tag ~= 0x30 then
    tlv.parse(node, data, DER)
    return
  end
  local index = 0
  while entries do
    local entry_tag, entry
    entry_tag, entry, entries = cp.asn1.split(entries)
    index = index + 1
    if entry_tag == 0x30 then
      local label = find_label(entry) or ('Certificate ' .. index)
      local path = find_path(entry)
      local object = util.node(node, 'item', label, path and cp.bytes.from_hex(path) or entry, path)
      if path then
        read_file(object, label, path, decode_x509)
      else
        tlv.parse(object, entry, DER)
      end
    end
  end
end

local function decode_od(node, data)
  local additional = 0
  while data do
    local tag, value
    tag, value, data = cp.asn1.split(data)
    local path = value and find_path(value)
    if path then
      local label, decoder
      if tag == 0xA0 then
        label, decoder = 'Private key directory', function(parent, content) tlv.parse(parent, content, DER) end
      elseif tag == 0xA8 then
        label, decoder = 'Authentication object directory', function(parent, content) tlv.parse(parent, content, DER) end
      elseif tag == 0xA4 then
        additional = additional + 1
        label = additional == 1 and 'Cardholder certificate directory' or 'Additional certificate directory'
        decoder = decode_certificate_directory
      elseif tag == 0xA5 then
        label, decoder = 'Trusted certificate directory', decode_certificate_directory
      elseif tag == 0xA6 then
        label, decoder = 'Useful certificate directory', decode_certificate_directory
      elseif tag == 0xA7 then
        label, decoder = 'Data container directory', function(parent, content) tlv.parse(parent, content, DER) end
      end
      if label then
        local directory = util.node(node, 'item', label, cp.bytes.from_hex(path), path)
        read_file(directory, label, path, decoder)
      end
    end
  end
end

local root = apdu.start('Finnish eID')
local application = util.node(root, 'application', 'FINEID application', nil, nil, FINEID_AID)
local aid = cp.bytes.from_hex(FINEID_AID)
local selected = util.transmit(cp.bytes.pack(8, 0, 0xA4, 0x04, 0x0C, #aid, aid))
if selected.status ~= 0x9000 then
  util.node(application, 'item', 'Application selection failed', selected.data, string.format('%04X', selected.status))
  return
end

read_file(application, 'EF.ATR', '3F002F01', function(node, data) tlv.parse(node, data, ATR_INFO) end)
read_file(application, 'EF.DIR', '3F002F00', function(node, data) tlv.parse(node, data, DIR) end)
read_file(application, 'EF.CIAInfo', '3F005032', decode_cia)
read_file(application, 'EF.OD', '3F005031', decode_od)
cp.log.info(string.format('Read FINEID public metadata and %d certificates', certificate_count))
