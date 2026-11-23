-- Ported from Cardpeek to the Cardpeek-ng Lua API on 2026-11-23.
-- @id openpgp
-- @title OpenPGP
-- @description Inspect public OpenPGP card data objects
-- @version 1.0.0
--
-- Parser for OpenPGP card 2.0 by Andreas Heiduk, 2014.
-- Based on the OpenPGP card specification.
-- Licensed under GPL-3.0-or-later. See the project NOTICE.md.

local cp = require('cardpeek')
local util = require('shared.lib.util')
local apdu = require('shared.lib.apdu')

local converters = {}

local function append(parent, class, label, data, alternative)
  return util.node(parent, class or 'item', label, data, alternative)
end

local function failure(parent, status, data)
  parent:set('value', 'unexpected response')
  append(parent, 'item', 'status', util.bytes(8, (status >> 8) & 0xFF, status & 0xFF))
  append(parent, 'item', 'response', data)
end

local function value(label, converter)
  return function(parent, data)
    local alternative = data and converter and converter(data) or nil
    return append(parent, 'item', label, data, alternative)
  end
end

local function hex(label) return value(label) end
local function integer(label) return value(label, function(data) return string.format('%.0f', util.number(data)) end) end
local function text(label)
  return value(label, function(data)
    if util.printable(data) then return util.format(data, '%P') end
    return nil
  end)
end
local function timestamp(label)
  return value(label, function(data) return os.date('!%Y-%m-%d %H:%M:%S UTC', util.number(data)) end)
end
local function mapped(label, mapping)
  return value(label, function(data) return mapping[util.number(data)] end)
end

local function structure(label, renderer, suppress_data)
  return function(parent, data)
    local node = append(parent, 'block', label, suppress_data and nil or data)
    renderer(node, data)
    return node
  end
end

local function fixed_elements(elements)
  return function(parent, data)
    local offset = 0
    for _, element in ipairs(elements) do
      local length = element[1]
      local part = util.sub(data, offset, offset + length - 1)
      element[2](parent, part or util.bytes(8))
      offset = offset + length
    end
    local additional = util.sub(data, offset)
    if additional and #additional > 0 then append(parent, 'item', 'additional data', additional) end
  end
end

local function fixed(label, elements, suppress_data)
  return structure(label, fixed_elements(elements), suppress_data)
end

local function tagged_elements(splitter, elements)
  return function(parent, data)
    while data do
      local tag, item, tail = splitter(data)
      if tag == nil then
        append(parent, 'item', 'Malformed tagged data', data)
        break
      end
      local renderer = elements[tag]
      if renderer then renderer(parent, item)
      else append(parent, 'item', string.format('tag 0x%04X', tag), item) end
      data = tail
    end
  end
end

local function asn1_elements(elements)
  return tagged_elements(cp.asn1.split, elements)
end

local function asn1(label, elements, suppress_data)
  return structure(label, asn1_elements(elements), suppress_data)
end

local function compact_split(data)
  if #data == 0 then return nil end
  local first = data[1]
  local tag, length = first & 0xF0, first & 0x0F
  return tag, util.sub(data, 1, length), util.sub(data, 1 + length)
end

local function bit_set(mask, label)
  return function(parent, data)
    if #data > 0 and (data[1] & mask) == mask then append(parent, 'item', label, util.bytes(8, mask)) end
  end
end

local function bit_clear(mask, label)
  return function(parent, data)
    if #data > 0 and (data[1] & mask) == 0 then append(parent, 'item', label, util.bytes(8, (~mask) & 0xFF)) end
  end
end

local function bit_hex(mask, label)
  return function(parent, data)
    local bits = #data > 0 and (data[1] & mask) or 0
    if bits ~= 0 then append(parent, 'item', label, util.bytes(8, bits)) end
  end
end

local function bits(label, handlers)
  local renderer = hex(label)
  return function(parent, data)
    local node = renderer(parent, data)
    for _, handler in ipairs(handlers) do handler(node, data) end
  end
end

local HISTORICAL_ELEMENTS = tagged_elements(compact_split, {
  [0x10] = hex('country code and national date'), [0x20] = hex('issuer identification number'),
  [0x30] = bits('card service data', {
    bit_set(0x80, 'application selection by full DF name'),
    bit_set(0x40, 'application selection by partial DF name'),
    bit_set(0x20, 'Data Objects available in DIR file'), bit_set(0x10, 'Data Objects available in ATR file'),
    bit_set(0x08, 'file IO services by READ BINARY command'),
    bit_clear(0x08, 'file IO services by READ RECORD command'), bit_hex(0x07, 'RFU'),
  }),
  [0x40] = hex('initial access data'), [0x50] = hex('card issuer data'),
  [0x60] = hex('pre-issuing data'), [0x70] = hex('card capabilities'),
})

local LIFE_STATUS = mapped('card life status', {
  [0] = 'no information', [3] = 'initialisation state', [5] = 'operational state',
})

local function historical_type_00(parent, data)
  if #data < 4 then return append(parent, 'item', 'Malformed historical bytes', data) end
  HISTORICAL_ELEMENTS(parent, util.sub(data, 1, #data - 4) or util.bytes(8))
  LIFE_STATUS(parent, util.sub(data, #data - 3, #data - 3))
  append(parent, 'item', 'status bytes', util.sub(data, #data - 2, #data - 1))
end

local HISTORICAL = structure('Historical Bytes', function(parent, data)
  if #data > 0 and data[1] == 0 then historical_type_00(parent, data)
  else append(parent, 'item', 'Unsupported historical byte category', data) end
end)

local APPLICATION_ID = fixed('Application ID', {
  { 5, hex('RID') }, { 1, hex('Application') }, { 2, hex('Version') },
  { 2, mapped('Manufacturer', {
    [1] = 'PPC Card Systems', [2] = 'Prism', [3] = 'OpenFortress', [4] = 'Wewid AB',
    [5] = 'ZeitControl', [0x2A] = 'Magrathea', [0xF517] = 'FSIJ', [0] = 'test card', [0xFFFF] = 'test card',
  }) },
  { 4, hex('Card serial number') }, { 2, hex('Reserved/future use') },
})

local CARDHOLDER = asn1('Cardholder data', {
  [0x005B] = text('Name'), [0x5F2D] = text('Language preferences'),
  [0x5F35] = mapped('Sex', { [0x31] = 'male', [0x32] = 'female', [0x39] = 'not announced' }),
})

local PW_STATUS = fixed('Password Status', {
  { 1, mapped('Signature PIN', { [0] = 'one PW1 per signature', [1] = 'multiple signatures allowed' }) },
  { 1, integer('Max Length PW1 (user)') }, { 1, integer('Max Length Reset Code') },
  { 1, integer('Max Length PW3 (admin)') }, { 1, integer('permissible retries PW1') },
  { 1, integer('permissible retries RC') }, { 1, integer('permissible retries PW3') },
})

local ALGORITHM = {
  { 1, hex('Algorithm ID') }, { 2, integer('Length of modulus') },
  { 2, integer('Length of public exponent') },
  { 1, mapped('private key format', {
    [0] = 'standard (e, p, q)', [1] = 'standard with modulus (n)', [2] = 'CRT', [3] = 'CRT with modulus',
  }) },
}

local APP_RELATED = asn1('Application related data', {
  [0x004F] = APPLICATION_ID, [0x5F52] = HISTORICAL,
  [0x0073] = asn1('Discretionary data objects', {
    [0x00C0] = fixed('Extended capabilities', {
      { 1, bits('Supported features', {
        bit_set(0x80, 'Secure Messaging'), bit_set(0x40, 'GET CHALLENGE'), bit_set(0x20, 'Key Import'),
        bit_set(0x10, 'PW1 status changeable'), bit_set(0x08, 'Private DOs'),
        bit_set(0x04, 'Algorithm attributes changeable'),
      }) },
      { 1, mapped('Secure Messaging Algorithm', { [0] = 'Triple DES', [1] = 'AES-128' }) },
      { 2, integer('Max length for GET CHALLENGE') }, { 2, integer('Max length Cardholder Certificate') },
      { 2, integer('Max length command data') }, { 2, integer('Max length response data') },
    }),
    [0x00C1] = fixed('Algorithm attributes (signature)', ALGORITHM),
    [0x00C2] = fixed('Algorithm attributes (decryption)', ALGORITHM),
    [0x00C3] = fixed('Algorithm attributes (authentication)', ALGORITHM),
    [0x00C4] = PW_STATUS,
    [0x00C5] = fixed('Fingerprints', {
      { 20, hex('Signature key') }, { 20, hex('Encryption key') }, { 20, hex('Authentication key') },
    }, true),
    [0x00C6] = fixed('CA Fingerprints', {
      { 20, hex('Fingerprint 1') }, { 20, hex('Fingerprint 2') }, { 20, hex('Fingerprint 3') },
    }, true),
    [0x00CD] = fixed('Generation timestamps', {
      { 4, timestamp('Signature key') }, { 4, timestamp('Encryption key') }, { 4, timestamp('Authentication key') },
    }),
  }, true),
}, true)

local SECURITY_SUPPORT = asn1('Security support template', {
  [0x0093] = integer('Digital signature counter'),
})

local FC_ITEMS = {
  [0x80] = integer('File size (excl. structural information)'),
  [0x81] = integer('File size (incl. structural information)'), [0x82] = hex('File descriptor'),
  [0x83] = hex('File ID'), [0x84] = hex('DF name'), [0x85] = hex('proprietary information'),
  [0x86] = hex('Security attributes'), [0x87] = hex('File ID with FCI extension'),
}

local FCI = asn1_elements({
  [0x62] = asn1('File control parameters', FC_ITEMS),
  [0x64] = asn1('File management data', FC_ITEMS),
  [0x6F] = asn1('File control information', FC_ITEMS),
})

local function data_object(tag, renderer)
  return function(parent)
    local response = apdu.get_data(tag)
    if response.status == 0x9000 then renderer(parent, response.data)
    else
      local node = renderer(parent, nil)
      if node then failure(node, response.status, response.data) end
    end
  end
end

local OBJECTS = {
  data_object(0x004F, APPLICATION_ID), data_object(0x0065, CARDHOLDER),
  data_object(0x5F50, text('URL of public key')), data_object(0x005E, hex('Login data')),
  data_object(0x0101, hex('Private DO 1')), data_object(0x0102, hex('Private DO 2')),
  data_object(0x0103, hex('Private DO 3')), data_object(0x0104, hex('Private DO 4')),
  data_object(0x5F52, HISTORICAL), data_object(0x006E, APP_RELATED),
  data_object(0x00C4, PW_STATUS), data_object(0x007A, SECURITY_SUPPORT),
  data_object(0x7F21, hex('Cardholder certificate')),
}

local root = apdu.start('OpenPGP Card')
local app = util.node(root, 'application', 'OpenPGP Application', nil, nil, 'D27600012401')
local response = apdu.select('#D27600012401')
if response.status == 0x9000 then
  FCI(app, response.data)
  for _, read in ipairs(OBJECTS) do read(app) end
else
  failure(app, response.status, response.data)
end
