-- @id finnish-etravel
-- @title Finnish eTravel
-- @description Inspect the Finnish Henkilokortti eMRTD application with PACE and extract the DG2 facial photograph
-- @version 1.0.0
-- @capabilities live, replay

local cp = require('cardpeek')
local util = require('shared.lib.util')
local apdu = require('shared.lib.apdu')
local tlv = require('cardpeek').tlv

local ETRAVEL_AID = 'A0000002471001'
local PACE_OID = cp.bytes.from_hex('04007F00070202040204')
local PACE_PARAMETER_ID = 13

local function secret(prompt)
  return cp.ui.secret(prompt) or ''
end

local function valid_credential(credential, value)
  if credential == 'can' then return value:match('^%d+$') ~= nil end
  return #value == 24 or (#value >= 88 and #value <= 128)
end

local function size(data)
  if #data < 2 then return nil end
  local first = data[2]
  if first < 0x80 then return first + 2 end
  local count = first & 0x7F
  if count == 0 or count > 2 then return nil end
  if #data < count + 2 then return 0 end
  local length = 0
  for index = 1, count do length = length * 256 + data[index + 2] end
  return length + count + 2
end

local function split(data)
  local ok, tag, value, tail = pcall(cp.asn1.split, data)
  if not ok or not tag then return nil end
  return tag, value, tail
end

local function oid(data)
  if #data == 0 then return '' end
  local values = {}
  local item = 0
  for value in data:iter() do
    item = item * 128 + (value & 0x7F)
    if value < 0x80 then
      table.insert(values, item)
      item = 0
    end
  end
  if #values > 0 then
    local first = values[1]
    local high = math.min(2, math.floor(first / 40))
    values[1] = high
    table.insert(values, 2, first - high * 40)
  end
  return table.concat(values, '.')
end

local function text(node, data)
  node:set('value', data)
  node:set('alternative', cp.bytes.format(data, '%C'))
end

local SECURITY_INFOS = {
  ['31'] = { 'Security infos' },
  ['30'] = { 'PACE info' },
  ['6'] = { 'Protocol', function(node, data)
    node:set('value', data)
    node:set('alternative', oid(data))
  end },
  ['2'] = { 'Version', tlv.parsers.number },
  ['80'] = { 'Parameter identifier', tlv.parsers.number },
  ['83'] = { 'Domain parameter' },
}

local DG1_REFERENCE = {
  ['61'] = { 'LDS1 eMRTD data group 1' },
  ['5C'] = { 'Data group tag list' },
  ['5F1F'] = { 'Machine readable zone', text },
}

local SOD_REFERENCE = {
  ['77'] = { 'Document security object' },
  ['30'] = { 'Sequence' },
  ['31'] = { 'Set' },
  ['6'] = { 'Object identifier', function(node, data)
    node:set('value', data)
    node:set('alternative', oid(data))
  end },
  ['2'] = { 'Integer', tlv.parsers.number },
  ['4'] = { 'Digest' },
  ['A0'] = { 'Signed data [0]' },
  ['A1'] = { 'Digest algorithms [1]' },
  ['A2'] = { 'Signed attributes [2]' },
  ['A3'] = { 'Certificates [3]' },
  ['A4'] = { 'Revocation information [4]' },
}

local function check_card_access(node, data)
  tlv.parse(node, data, SECURITY_INFOS)
  local found = false
  local tag, sequence = split(data)
  if tag ~= 0x31 then return false end
  local remaining = sequence
  while #remaining > 0 do
    local info_tag, info, tail = split(remaining)
    if info_tag ~= 0x30 then return false end
    local protocol_tag, protocol, parameters = split(info)
    if protocol_tag == 0x06 and protocol == PACE_OID then
      local parameter_tag, parameter, rest = split(parameters or cp.bytes.pack(8))
      local version_tag, version = split(parameters or cp.bytes.pack(8))
      if version_tag == 0x02 then
        local value = cp.bytes.number(version)
        if value ~= 2 then return false end
      end
      if parameter_tag == 0x02 then parameter_tag, parameter, rest = split(rest or cp.bytes.pack(8)) end
      if parameter_tag == 0x80 and cp.bytes.number(parameter) == PACE_PARAMETER_ID then
        found = true
      end
    end
    remaining = tail or cp.bytes.pack(8)
  end
  return found
end

local function read_plain_file(parent, label, fid, decoder)
  local file = util.node(parent, 'file', label, nil, nil, fid)
  local selected = util.transmit(cp.bytes.pack(8, 0, 0xA4, 0x02, 0x0C, 0x02, fid))
  if selected.status ~= 0x9000 then
    util.node(file, 'item', 'Selection failed', selected.data, string.format('%04X', selected.status))
    return nil
  end
  local data = cp.bytes.pack(8)
  local expected
  while not expected or #data < expected do
    local remaining = expected and expected - #data
    local length = remaining and remaining <= 255 and remaining or 0
    local response = apdu.read_binary(#data, length)
    if response.status ~= 0x9000 then
      util.node(file, 'item', 'Read failed', response.data, string.format('%04X', response.status))
      return nil
    end
    if #response.data == 0 then return nil end
    data = data .. response.data
    expected = size(data)
  end
  file:set('value', data)
  if decoder then decoder(file, data) end
  return file, data
end

local function establish_pace(parent, credential, value)
  local session = cp.crypto.pace_new(credential, cp.bytes.from_string(value))
  local command = cp.crypto.pace_handshake(session)
  local responses = 0
  while command do
    local response = util.transmit(command)
    local ok, next_command = pcall(cp.crypto.pace_handshake, session, response)
    if not ok then
      util.node(parent, 'item', 'PACE authentication failed', nil, tostring(next_command))
      return nil
    end
    command = next_command
    responses = responses + 1
    if responses > 8 then return nil end
  end
  return session
end

local function protected_transmit(session, command)
  local response = util.transmit(cp.crypto.pace_protect(session, command))
  local status = response.status
  if status == 0x9000 then
    return cp.crypto.pace_unprotect(session, cp.bytes.pack(8, response.data, 0x90, 0x00))
  end
  return response
end

local function read_secure_file(session, parent, label, fid, decoder)
  local file = util.node(parent, 'file', label, nil, nil, fid)
  local selected = protected_transmit(session, cp.bytes.pack(8, 0, 0xA4, 0x02, 0x0C, 0x02, fid))
  if selected.status ~= 0x9000 then
    util.node(file, 'item', 'Selection failed', selected.data, string.format('%04X', selected.status))
    return
  end
  local data = cp.bytes.pack(8)
  local expected
  while not expected or #data < expected do
    local remaining = expected and expected - #data
    local length = remaining and remaining <= 255 and remaining or 0
    local high = (#data >> 8) & 0xFF
    local low = #data & 0xFF
    local response = protected_transmit(session, cp.bytes.pack(8, 0, 0xB0, high, low, length))
    if response.status ~= 0x9000 then
      util.node(file, 'item', 'Read failed', response.data, string.format('%04X', response.status))
      return
    end
    if #response.data == 0 then
      util.node(file, 'item', 'Read failed', nil, 'Card returned no data before the declared object length')
      return
    end
    data = data .. response.data
    expected = size(data)
    if not expected then
      util.node(file, 'item', 'Read failed', data, 'Invalid DER length')
      return
    end
  end
  if #data ~= expected then
    util.node(file, 'item', 'Read failed', data, 'Data length exceeds the declared object length')
    return
  end
  file:set('value', data)
  if decoder then decoder(file, data) end
end

local function number(data, first, length)
  local value = 0
  for index = first, first + length - 1 do value = value * 256 + data[index] end
  return value
end

local function decode_face(content, value)
  if #value < 4 or value:slice(1, 4):to_hex() ~= '46414300' then
    util.node(content, 'item', 'Unexpected biometric format', value)
    return
  end
  if #value < 14 then return end
  local faces = number(value, 13, 2)
  util.node(content, 'item', 'Number of facial images', faces)
  local offset = 15
  for index = 1, faces do
    if #value < offset + 31 then return end
    local record_start = offset
    local record_length = number(value, offset, 4)
    if record_length < 32 or record_start + record_length - 1 > #value then
      util.node(content, 'item', 'Invalid facial record length', record_length)
      return
    end
    local features = number(value, offset + 4, 2)
    local face = util.node(content, 'item', 'Facial record ' .. index, nil, string.format('%d bytes', record_length))
    local image_type = value[offset + 20]
    local width = number(value, offset + 22, 2)
    local height = number(value, offset + 24, 2)
    local image_offset = offset + 32 + features * 8
    local image_length = record_start + record_length - image_offset
    util.node(face, 'item', 'Image width', width)
    util.node(face, 'item', 'Image height', height)
    if image_length > 0 and image_offset + image_length - 1 <= #value then
      local image = value:slice(image_offset, image_length)
      local image_node = util.node(face, 'image', 'Facial photograph', image)
      if #image >= 2 and image[1] == 0xFF and image[2] == 0xD8 then
        image_node:set('mime_type', 'image/jpeg')
      elseif #image >= 12 and image:slice(1, 12):to_hex() == '0000000C6A5020200D0A870A' then
        image_node:set('mime_type', 'image/jp2')
      else
        image_node:set('mime_type', 'application/octet-stream')
        cp.log.warning('Could not identify the facial photograph format')
      end
      util.node(face, 'item', 'Image data type', image_type)
    end
    offset = record_start + record_length
  end
end

local function decode_dg2(node, data)
  local tag, value = split(data)
  if tag ~= 0x75 then
    util.node(node, 'item', 'Unexpected DG2 tag', data)
    return
  end
  local group_tag, group = split(value)
  if group_tag ~= 0x7F61 then
    util.node(node, 'item', 'Missing biometric information group', value)
    return
  end
  local remaining = group
  local count_tag, count_value, count_tail = split(remaining)
  if count_tag == 0x02 then
    util.node(node, 'item', 'Biometric instance count', cp.bytes.number(count_value))
    remaining = count_tail or cp.bytes.pack(8)
  end
  while #remaining > 0 do
    local template_tag, template, tail = split(remaining)
    if template_tag ~= 0x7F60 then return end
    local biometric = template
    local header_tag, _, header_tail = split(biometric)
    if header_tag == 0xA1 then biometric = header_tail or cp.bytes.pack(8) end
    local block_tag, block = split(biometric)
    if block_tag == 0x5F2E or block_tag == 0x7F2E then
      local content = util.node(node, 'body', 'Facial biometric data', block)
      decode_face(content, block)
    end
    remaining = tail or cp.bytes.pack(8)
  end
end

local root = apdu.start('Finnish eTravel')
local card_access, card_access_data = read_plain_file(root, 'EF.CardAccess', '011C')
local application = util.node(root, 'application', 'ICAO eTravel application', nil, nil, ETRAVEL_AID)
if not card_access then return end
local supported = check_card_access(card_access:append('body', 'Card access security information'), card_access_data)
if not supported then
  util.node(application, 'item', 'Unsupported PACE profile', nil, 'Require PACE-ECDH-GM-AES-CBC-CMAC-256 with Brainpool P-384r1')
  return
end

local method = cp.ui.question('Use CAN for PACE? Cancel to use the machine-readable zone.')
local credential = method and 'can' or 'mrz'
local value = secret(method and 'Enter the card access number (CAN)' or 'Enter the three MRZ access fields, or the complete second MRZ line, without spaces')
if not valid_credential(credential, value) then
  util.node(application, 'item', 'Invalid PACE credential', nil, credential == 'can' and 'Enter the numeric card access number' or 'Enter the document number, birth date, and expiry date fields, including check digits, or the complete second MRZ line')
  return
end

local session = establish_pace(application, credential, value)
if not session then return end
util.node(application, 'item', 'PACE authentication', nil, 'PACE-ECDH-GM-AES-CBC-CMAC-256, Brainpool P-384r1, ' .. credential:upper())

local selected = protected_transmit(session, cp.bytes.pack(8, 0, 0xA4, 0x04, 0x0C, 0x07, ETRAVEL_AID))
if selected.status ~= 0x9000 then
  util.node(application, 'item', 'Application selection failed', selected.data, string.format('%04X', selected.status))
  return
end

read_secure_file(session, application, 'EF.DG1', '0101', function(node, data) tlv.parse(node, data, DG1_REFERENCE) end)
read_secure_file(session, application, 'EF.DG2', '0102', decode_dg2)
read_secure_file(session, application, 'EF.DG14', '010E', function(node, data) tlv.parse(node, data, SECURITY_INFOS) end)
read_secure_file(session, application, 'EF.SOD', '011D', function(node, data) tlv.parse(node, data, SOD_REFERENCE) end)
cp.log.info('Read the Finnish eTravel public data groups and facial photograph')
