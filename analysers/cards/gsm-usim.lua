-- GSM SIM and USIM filesystem analyser with optional PIN1 verification.
-- @id gsm-usim
-- @title GSM SIM and USIM
-- @description Inspect GSM SIM and USIM files with optional PIN1 verification
-- @version 1.0.0

local cardpeek = require("cardpeek")

local CONFIG = {
  offer_pin_verification = true,
  transparent_chunk = 232,
  max_records = 255
}

local STATS = {
  files = 0, records = 0, missing = 0, denied = 0,
  read_errors = 0, parse_errors = 0, sensitive_skipped = 0
}

local PIN_STATE = { asked = false, hint = nil }

local function make_bytes(...)
  local values = {}
  for _, value in ipairs({ ... }) do
    if type(value) == 'string' then
      value = cardpeek.bytes.from_hex(value)
    end
    if type(value) == 'userdata' then
      for item in value:iter() do table.insert(values, item) end
    else
      table.insert(values, value)
    end
  end
  return cardpeek.bytes.new(8, values)
end

local function byte(data, pos)
  if data == nil or pos < 0 or pos >= #data then return nil end
  return data[pos + 1]
end

local function empty_bytes()
  return make_bytes()
end

local function slice(data, first, last)
  if data == nil or #data == 0 or first >= #data then return empty_bytes() end
  if first < 0 then first = 0 end
  if last == nil or last >= #data then last = #data - 1 end
  if last < first then return empty_bytes() end
  return data:slice(first + 1, last - first + 1)
end

local function concat_data(a, b)
  if a == nil or #a == 0 then return b or empty_bytes() end
  if b == nil or #b == 0 then return a end
  return a .. b
end

local function hex(data)
  if data == nil then return '' end
  return tostring(data)
end

local function uint(data)
  local n = 0
  if data == nil then return 0 end
  for i = 0, #data - 1 do n = n * 256 + byte(data, i) end
  return n
end

local function all_ff(data)
  if data == nil or #data == 0 then return true end
  for i = 0, #data - 1 do
    if byte(data, i) ~= 0xFF then return false end
  end
  return true
end

local function display_text(value)
  local text = tostring(value)
  return (text:gsub('[%z\1-\8\11\12\14-\31]', function(char)
    return string.format('\\x%02X', string.byte(char))
  end))
end

local function append(parent, classname, label, value, alt, id)
  local node = parent:append(classname, label)
  if value ~= nil then
    if type(value) == 'userdata' then
      node:set('value', value)
    else
      node:set('alternative', display_text(value))
    end
  end
  if alt ~= nil then node:set('alternative', display_text(alt)) end
  if id ~= nil then node:set('identifier', tostring(id)) end
  return node
end

local function set_alt(node, text)
  if node ~= nil and text ~= nil then node:set('alternative', display_text(text)) end
  return node
end

local function sw_text(sw)
  local known = {
    [0x9000] = 'success',
    [0x6982] = 'security status not satisfied',
    [0x6983] = 'authentication method blocked',
    [0x6984] = 'referenced data invalidated',
    [0x6985] = 'conditions of use not satisfied',
    [0x6A82] = 'file or application not found',
    [0x6A83] = 'record not found',
    [0x6A86] = 'incorrect P1/P2',
    [0x6A88] = 'referenced data not found',
    [0x6B00] = 'incorrect offset or parameters',
    [0x6D00] = 'instruction not supported',
    [0x6E00] = 'class not supported',
    [0x6F00] = 'technical error',
    [0x9404] = 'file not found',
    [0x9802] = 'no CHV initialized',
    [0x9804] = 'access condition not fulfilled / verification failed',
    [0x9840] = 'CHV or UNBLOCK CHV blocked'
  }
  if known[sw] then return string.format('%04X (%s)', sw, known[sw]) end
  if (sw &  0xFFF0) == 0x63C0 then
    return string.format('%04X (verification failed; %d attempt(s) remain)', sw, (sw &  0x0F))
  end
  if (sw &  0xFF00) == 0x6100 then
    return string.format('%04X (%d response byte(s) available)', sw, (sw &  0xFF))
  end
  return string.format('%04X', sw)
end

local function is_missing(sw)
  return sw == 0x6A82 or sw == 0x9404
end

local function is_access_denied(sw)
  return sw == 0x6982 or sw == 0x9804
end

local function log_warning(message)
  cardpeek.log.warning(message)
end

-- Transmit an APDU and collect 61xx (and legacy GSM 9Fxx) response data.
local function transmit(command, cla, legacy_response)
  local result = empty_bytes()
  local current = command
  local rounds = 0
  local sw, response

  repeat
    local exchange, failure = cardpeek.card.transmit(current)
    assert(failure == nil, failure and failure.message or 'APDU transmission failed')
    sw, response = exchange.status, exchange.data
    result = concat_data(result, response)
    rounds = rounds + 1
    local sw1 = (sw &  0xFF00)
    if sw1 == 0x6100 or (legacy_response and sw1 == 0x9F00) then
      current = make_bytes(cla, 0xC0, 0x00, 0x00, (sw &  0xFF))
    else
      break
    end
  until rounds >= 12

  if rounds >= 12 then log_warning('Too many GET RESPONSE rounds; returning partial data') end
  return sw, result
end

local function select_file(session, fid, kind, without_le)
  local data = make_bytes(fid)
  local p1 = 0x00
  if kind == 'application' then
    p1 = 0x04
  elseif kind == 'file' and not session.legacy then
    p1 = 0x02
  end
  local omit_le = without_le or (kind == 'application' and session.application_without_le)
  local command
  if omit_le then
    command = make_bytes(session.cla, 0xA4, p1, 0x00, #data, data)
  else
    command = make_bytes(session.cla, 0xA4, p1, 0x00, #data, data, 0x00)
  end
  return transmit(command, session.cla, session.cla == 0xA0)
end

local function read_binary(session, offset, length)
  local le = length
  if le == 256 then le = 0 end
  local command = make_bytes(session.cla, 0xB0,
    ((offset >> 8) & 0x7F), (offset & 0xFF), le)
  return transmit(command, session.cla, false)
end

local function read_record(session, record_number, length)
  local le = length
  if le == 256 then le = 0 end
  local command = make_bytes(session.cla, 0xB2, record_number, 0x04, le)
  return transmit(command, session.cla, false)
end

local function pin_block(pin, legacy)
  local values = {}
  for i = 1, #pin do table.insert(values, string.byte(pin, i)) end
  if legacy then while #values < 8 do table.insert(values, 0xFF) end end
  return cardpeek.bytes.new(8, values)
end

local function ask_question(prompt)
  local ok, answer = pcall(cardpeek.ui.question, prompt)
  return ok and answer == true
end

local function show_notice(message)
  pcall(cardpeek.ui.notice, message)
end

local function offer_verification(session)
  if not CONFIG.offer_pin_verification or PIN_STATE.asked then return false end
  PIN_STATE.asked = true

  local warning = 'A file requires PIN1/CHV1. Verification changes card security state and a wrong PIN can block it.'
  if PIN_STATE.hint then warning = warning .. '\nReported attempts remaining: ' .. PIN_STATE.hint end
  warning = warning .. '\nOnly one verification attempt is allowed in this run. Verify PIN1/CHV1 once?'
  if not ask_question(warning) then return false end

  local ok, pin = pcall(cardpeek.ui.secret, 'Enter PIN1/CHV1 (4-8 digits; empty cancels)')
  if not ok or pin == nil or pin == '' then return false end
  if not string.match(pin, '^%d+$') or #pin < 4 or #pin > 8 then
    show_notice('PIN not sent: enter exactly 4 to 8 decimal digits.')
    return false
  end

  local data = pin_block(pin, session.cla == 0xA0)
  local command = make_bytes(session.cla, 0x20, 0x00, 0x01, #data, data)
  local sw = transmit(command, session.cla, false)
  if sw == 0x9000 then
    cardpeek.log.info('PIN1/CHV1 verified; will now retry the previously failed operation once')
    show_notice('PIN1/CHV1 verified. Will now retry the previously failed operation once.')
    return true
  end

  if (sw & 0xFFF0) == 0x63C0 then PIN_STATE.hint = sw & 0x0F end
  log_warning('PIN1/CHV1 verification failed: ' .. sw_text(sw) .. '; no further attempt in this run')
  show_notice('PIN verification was not successful: ' .. sw_text(sw) .. '\nNo further verification will be attempted in this run.')
  return false
end

-- BER-TLV parsing with strict bounds checks. Returned values own their byte slices.
local function parse_tlv(data, first, last)
  local items = {}
  local pos = first or 0
  local stop = last or (#data - 1)

  while pos <= stop and pos < #data do
    local start = pos
    local tag = byte(data, pos)
    pos = pos + 1
    if tag == 0x00 or tag == 0xFF then break end

    if (tag &  0x1F) == 0x1F then
      local more = true
      while more and pos <= stop do
        local part = byte(data, pos)
        tag = tag * 256 + part
        pos = pos + 1
        more = (part &  0x80) ~= 0
      end
      if more then break end
    end

    local length = byte(data, pos)
    if length == nil then break end
    pos = pos + 1
    if length == 0x81 or length == 0x82 then
      local count = length - 0x80
      length = 0
      for _ = 1, count do
        local part = byte(data, pos)
        if part == nil then return items end
        length = length * 256 + part
        pos = pos + 1
      end
    elseif length >= 0x80 then
      break -- Indefinite lengths are not valid in UICC file data.
    end

    if pos + length - 1 > stop or pos + length > #data then
      table.insert(items, { tag = tag, malformed = true, start = start })
      break
    end

    local value = length > 0 and slice(data, pos, pos + length - 1) or empty_bytes()
    table.insert(items, {
      tag = tag, value = value, start = start, length = length,
      constructed = (tag &  0x20) ~= 0
    })
    pos = pos + length
  end
  return items
end

local function tlv_first(items, tag)
  for _, item in ipairs(items) do
    if item.tag == tag and not item.malformed then return item end
  end
  return nil
end

local function collect_tlv_tag(data, wanted, output, depth)
  depth = depth or 0
  if data == nil or depth > 5 then return end
  for _, item in ipairs(parse_tlv(data)) do
    if item.tag == wanted then table.insert(output, item.value) end
    if item.constructed and #item.value > 0 then
      collect_tlv_tag(item.value, wanted, output, depth + 1)
    end
  end
end

local FCP_TAG_NAMES = {
  [0x62] = 'FCP template', [0x6F] = 'FCI template', [0x61] = 'Application template',
  [0x80] = 'File size', [0x81] = 'Total file size', [0x82] = 'File descriptor',
  [0x83] = 'File identifier', [0x84] = 'DF name (AID)', [0x88] = 'Short file identifier',
  [0x8A] = 'Life cycle status', [0x8B] = 'Security attributes (referenced)',
  [0x8C] = 'Security attributes (compact)', [0xAB] = 'Security attributes (expanded)',
  [0xA5] = 'Proprietary information', [0xC6] = 'PIN status template'
}

local STRUCTURES = {
  [0] = 'no information', [1] = 'transparent', [2] = 'linear fixed',
  [3] = 'cyclic', [4] = 'BER-TLV structured'
}
local LEGACY_STRUCTURES = {
  [0] = 'transparent', [1] = 'linear fixed', [3] = 'cyclic'
}

local function parse_metadata(response)
  local meta = { format = 'unknown', structure = 'unknown' }
  if response == nil or #response == 0 then return meta end

  if byte(response, 0) == 0x62 or byte(response, 0) == 0x6F then
    local outer = parse_tlv(response)
    local template = tlv_first(outer, 0x62) or tlv_first(outer, 0x6F)
    if template then
      local fields = parse_tlv(template.value)
      meta.format = 'fcp'
      meta.fields = fields
      local fd = tlv_first(fields, 0x82)
      local size = tlv_first(fields, 0x80)
      local fid = tlv_first(fields, 0x83)
      local aid = tlv_first(fields, 0x84)
      local sfi = tlv_first(fields, 0x88)
      if size then meta.file_size = uint(size.value) end
      if fid then meta.file_id = hex(fid.value) end
      if aid then meta.aid = hex(aid.value) end
      if sfi and #sfi.value > 0 then meta.sfi = byte(sfi.value, 0) end
      if fd and #fd.value >= 2 then
        meta.structure = STRUCTURES[(byte(fd.value, 0) & 0x07)] or 'unknown'
        if #fd.value >= 5 then
          meta.record_length = byte(fd.value, 2) * 256 + byte(fd.value, 3)
          meta.record_count = byte(fd.value, 4)
        end
      end
      return meta
    end
  end

  if #response >= 15 then
    meta.format = 'gsm'
    meta.file_id = string.format('%02X%02X', byte(response, 4), byte(response, 5))
    local file_type = byte(response, 6)
    if file_type == 1 or file_type == 2 then
      meta.kind = 'df'
      meta.chv1_status = byte(response, 18)
    elseif file_type == 4 then
      meta.kind = 'file'
      meta.file_size = byte(response, 2) * 256 + byte(response, 3)
      meta.structure = LEGACY_STRUCTURES[byte(response, 13)] or 'unknown'
      if meta.structure ~= 'transparent' then
        meta.record_length = byte(response, 14)
        if meta.record_length and meta.record_length > 0 then
          meta.record_count = math.floor(meta.file_size / meta.record_length)
        end
      end
    end
  end
  return meta
end

local function append_metadata(node, response, meta)
  local header = append(node, 'header', 'SELECT response', response)
  if meta.format == 'fcp' then
    set_alt(header, string.format('FCP; %s; size=%s; record length=%s; records=%s',
      meta.structure, tostring(meta.file_size), tostring(meta.record_length), tostring(meta.record_count)))
    for _, item in ipairs(meta.fields or {}) do
      local label = FCP_TAG_NAMES[item.tag] or string.format('Tag %X', item.tag)
      append(header, 'item', label, item.value, nil, string.format('%X', item.tag))
    end
  elseif meta.format == 'gsm' then
    set_alt(header, string.format('Legacy GSM descriptor; %s; size=%s; record length=%s; records=%s',
      meta.structure, tostring(meta.file_size), tostring(meta.record_length), tostring(meta.record_count)))
    if meta.chv1_status ~= nil then
      append(header, 'item', 'CHV1 status', string.format('0x%02X', meta.chv1_status))
      PIN_STATE.hint = meta.chv1_status & 0x07
    end
  else
    set_alt(header, 'Unrecognized or empty SELECT response')
  end
end


---------------------------------------------------------------------------
-- Text, BCD, PLMN, and common elementary-file decoders
---------------------------------------------------------------------------

local GSM7 = {
  string.char(64), string.char(194, 163), string.char(36), string.char(194, 165), string.char(195, 168), string.char(195, 169), string.char(195, 185), string.char(195, 172),
  string.char(195, 178), string.char(195, 135), string.char(10), string.char(195, 152), string.char(195, 184), string.char(13), string.char(195, 133), string.char(195, 165),
  string.char(206, 148), string.char(95), string.char(206, 166), string.char(206, 147), string.char(206, 155), string.char(206, 169), string.char(206, 160), string.char(206, 168),
  string.char(206, 163), string.char(206, 152), string.char(206, 158), string.char(23), string.char(195, 134), string.char(195, 166), string.char(195, 159), string.char(195, 137),
  string.char(32), string.char(33), string.char(34), string.char(35), string.char(194, 164), string.char(37), string.char(38), string.char(39),
  string.char(40), string.char(41), string.char(42), string.char(43), string.char(44), string.char(45), string.char(46), string.char(47),
  string.char(48), string.char(49), string.char(50), string.char(51), string.char(52), string.char(53), string.char(54), string.char(55),
  string.char(56), string.char(57), string.char(58), string.char(59), string.char(60), string.char(61), string.char(62), string.char(63),
  string.char(194, 161), string.char(65), string.char(66), string.char(67), string.char(68), string.char(69), string.char(70), string.char(71),
  string.char(72), string.char(73), string.char(74), string.char(75), string.char(76), string.char(77), string.char(78), string.char(79),
  string.char(80), string.char(81), string.char(82), string.char(83), string.char(84), string.char(85), string.char(86), string.char(87),
  string.char(88), string.char(89), string.char(90), string.char(195, 132), string.char(195, 150), string.char(195, 145), string.char(195, 156), string.char(194, 167),
  string.char(194, 191), string.char(97), string.char(98), string.char(99), string.char(100), string.char(101), string.char(102), string.char(103),
  string.char(104), string.char(105), string.char(106), string.char(107), string.char(108), string.char(109), string.char(110), string.char(111),
  string.char(112), string.char(113), string.char(114), string.char(115), string.char(116), string.char(117), string.char(118), string.char(119),
  string.char(120), string.char(121), string.char(122), string.char(195, 164), string.char(195, 182), string.char(195, 177), string.char(195, 188), string.char(195, 160)
}

local GSM7_EXT = { [0x0A] = string.char(12), [0x14] = string.char(94), [0x28] = string.char(123), [0x29] = string.char(125), [0x2F] = string.char(92), [0x3C] = string.char(91), [0x3D] = string.char(126), [0x3E] = string.char(93), [0x40] = string.char(124), [0x65] = string.char(226, 130, 172)
}

local BCD = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'a', 'b', 'c', 'F' }

local function swap_bcd(data, stop_at_fill)
  local output = {}
  if data == nil then return '' end
  for i = 0, #data - 1 do
    local value = byte(data, i)
    local low = (value &  0x0F)
    local high = (value >>  4)
    if stop_at_fill and low == 0x0F then break end
    table.insert(output, BCD[low + 1])
    if stop_at_fill and high == 0x0F then break end
    table.insert(output, BCD[high + 1])
  end
  return table.concat(output)
end

local function utf8_char(cp)
  if cp < 0 or cp > 0x10FFFF or (cp >= 0xD800 and cp <= 0xDFFF) or cp == 0xFFFE or cp == 0xFFFF then cp = 0xFFFD end
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char((0xC0 |  (cp >>  6)), (0x80 |  (cp &  0x3F)))
  elseif cp < 0x10000 then
    return string.char((0xE0 |  (cp >>  12)),
      (0x80 | ((cp >> 6) & 0x3F)), (0x80 | (cp & 0x3F)))
  end
  return string.char((0xF0 | (cp >> 18)),
    (0x80 | ((cp >> 12) & 0x3F)),
    (0x80 | ((cp >> 6) & 0x3F)), (0x80 | (cp & 0x3F)))
end

local function decode_ucs2(data)
  local output = {}
  local pos = 0
  while pos + 1 < #data do
    local cp = byte(data, pos) * 256 + byte(data, pos + 1)
    pos = pos + 2
    if cp >= 0xD800 and cp <= 0xDBFF and pos + 1 < #data then
      local low = byte(data, pos) * 256 + byte(data, pos + 1)
      if low >= 0xDC00 and low <= 0xDFFF then
        cp = 0x10000 + (cp - 0xD800) * 0x400 + (low - 0xDC00)
        pos = pos + 2
      end
    end
    table.insert(output, utf8_char(cp))
  end
  if pos < #data then table.insert(output, utf8_char(0xFFFD)) end
  return table.concat(output)
end

local function decode_gsm7_codes(codes)
  local output = {}
  local i = 1
  while i <= #codes do
    local code = codes[i]
    if code == 0x1B and i < #codes then
      i = i + 1
      table.insert(output, GSM7_EXT[codes[i]] or '?')
    elseif code == 0x1B then
      table.insert(output, '?')
    else
      table.insert(output, GSM7[code + 1] or '?')
    end
    i = i + 1
  end
  return table.concat(output)
end

local function trim_ff_length(data)
  local length = #data
  while length > 0 and byte(data, length - 1) == 0xFF do length = length - 1 end
  return length
end

local function decode_alpha(data)
  if data == nil then return '' end
  local length = trim_ff_length(data)
  if length == 0 then return '' end
  local first = byte(data, 0)

  if first == 0x80 then
    return decode_ucs2(slice(data, 1, length - 1))
  elseif first == 0x81 and length >= 3 then
    local count = math.min(byte(data, 1), length - 3)
    local base = byte(data, 2) * 128
    local output = {}
    for i = 0, count - 1 do
      local value = byte(data, 3 + i)
      if (value &  0x80) ~= 0 then
        table.insert(output, utf8_char(base + (value &  0x7F)))
      else
        table.insert(output, decode_gsm7_codes({ value }))
      end
    end
    return table.concat(output)
  elseif first == 0x82 and length >= 4 then
    local count = math.min(byte(data, 1), length - 4)
    local base = byte(data, 2) * 256 + byte(data, 3)
    local output = {}
    for i = 0, count - 1 do
      local value = byte(data, 4 + i)
      if (value &  0x80) ~= 0 then
        table.insert(output, utf8_char(base + (value &  0x7F)))
      else
        table.insert(output, decode_gsm7_codes({ value }))
      end
    end
    return table.concat(output)
  end

  local codes = {}
  for i = 0, length - 1 do table.insert(codes, byte(data, i)) end
  return decode_gsm7_codes(codes)
end

local function decode_packed_gsm7(data, septets, skip_septets)
  local output = {}
  skip_septets = skip_septets or 0
  septets = math.max(0, (septets or 0) - skip_septets)
  for index = 0, septets - 1 do
    local bitpos = (index + skip_septets) * 7
    local pos = math.floor(bitpos / 8)
    local shift = bitpos % 8
    local window = byte(data, pos)
    if window == nil then break end
    local next_byte = byte(data, pos + 1) or 0
    window = window + next_byte * 256
    table.insert(output, (window >> shift) & 0x7F)
  end
  return decode_gsm7_codes(output)
end

local function decode_iccid(data)
  if #data == 0 then return 'Empty ICCID' end
  local digits = swap_bcd(data, false):gsub('F+$', '')
  return digits .. (string.match(digits, '^%d+$') and '' or ' [contains non-decimal digits]')
end

local function decode_imsi(data)
  if #data < 2 then return 'Malformed IMSI: fewer than 2 bytes' end
  local length = byte(data, 0)
  if length < 1 or length > 8 or length > #data - 1 then
    return string.format('Malformed IMSI length: %s', tostring(length))
  end
  local digits = swap_bcd(slice(data, 1, length), true)
  local imsi = digits:sub(2):gsub('F+$', '')
  return imsi .. string.format(' [length byte=%d]', length)
end

local function decode_languages(data)
  local languages = {}
  for i = 0, #data - 1, 2 do
    local a, b = byte(data, i), byte(data, i + 1)
    if a == nil or (a == 0xFF and b == 0xFF) then break end
    if b == nil then
      table.insert(languages, string.format('%02X [truncated]', a))
      break
    end
    table.insert(languages, string.char(a, b))
  end
  return #languages > 0 and table.concat(languages, ', ') or '(not set)'
end

local LP_LANGUAGES = {
  [0x00] = 'German', [0x01] = 'English', [0x02] = 'Italian', [0x03] = 'French',
  [0x04] = 'Spanish', [0x05] = 'Dutch', [0x06] = 'Swedish', [0x07] = 'Danish',
  [0x08] = 'Portuguese', [0x09] = 'Finnish', [0x0A] = 'Norwegian', [0x0B] = 'Greek',
  [0x0C] = 'Turkish', [0x0D] = 'Hungarian', [0x0E] = 'Polish', [0x0F] = 'Korean',
  [0x10] = 'Chinese', [0x11] = 'Russian', [0x12] = 'Japanese'
}

-- DF.GSM EF.LP uses one-byte language indicators from 3GPP TS 23.038.
local function decode_lp(data)
  local languages = {}
  for i = 0, #data - 1 do
    local code = byte(data, i)
    if code == 0xFF then break end
    table.insert(languages, LP_LANGUAGES[code] or string.format('Reserved (0x%02X)', code))
  end
  return #languages > 0 and table.concat(languages, ', ') or '(not set)'
end

local function decode_plmn(data)
  if data == nil or #data < 3 or all_ff(slice(data, 0, 2)) then return '(empty)' end
  local a, b, c = byte(data, 0), byte(data, 1), byte(data, 2)
  local mcc = string.format('%d%d%d', (a &  0x0F), (a >>  4), (b &  0x0F))
  local mnc3 = (b >>  4)
  local mnc = string.format('%d%d', (c &  0x0F), (c >>  4))
  if mnc3 ~= 0x0F then mnc = mnc .. string.format('%d', mnc3) end
  return mcc .. '-' .. mnc
end

local function decode_plmn_list(data)
  local entries = {}
  for i = 0, #data - 1, 3 do
    if i + 2 >= #data then
      table.insert(entries, '[truncated PLMN]')
      break
    end
    local value = decode_plmn(slice(data, i, i + 2))
    if value == '(empty)' and #entries == 0 then return '(not set)' end
    if value ~= '(empty)' then table.insert(entries, value) end
  end
  return #entries > 0 and table.concat(entries, ', ') or '(not set)'
end

local function decode_plmn_act(data)
  local entries = {}
  for i = 0, #data - 1, 5 do
    if i + 4 >= #data then
      table.insert(entries, '[truncated PLMN+AcT entry]')
      break
    end
    local plmn = decode_plmn(slice(data, i, i + 2))
    if plmn ~= '(empty)' then
      local act = byte(data, i + 3) * 256 + byte(data, i + 4)
      local names = {}
      if (act &  0x8000) ~= 0 then table.insert(names, 'UTRAN') end
      if (act &  0x4000) ~= 0 then
        if (act &  0x2000) ~= 0 then
          table.insert(names, 'E-UTRAN WB-S1')
        elseif (act &  0x1000) ~= 0 then
          table.insert(names, 'E-UTRAN NB-S1')
        else
          table.insert(names, 'E-UTRAN WB-S1 + NB-S1')
        end
      end
      if (act &  0x0800) ~= 0 then table.insert(names, 'NG-RAN') end
      if (act &  0x0080) ~= 0 then table.insert(names, 'GSM') end
      if (act &  0x0008) ~= 0 then table.insert(names, 'EC-GSM-IoT') end
      if (act &  0x0040) ~= 0 then table.insert(names, 'GSM COMPACT') end
      if (act &  0x0020) ~= 0 then table.insert(names, 'cdma2000 HRPD') end
      if (act &  0x0010) ~= 0 then table.insert(names, 'cdma2000 1xRTT') end
      if #names == 0 then table.insert(names, string.format('AcT=%04X', act)) end
      table.insert(entries, plmn .. ' [' .. table.concat(names, ', ') .. ']')
    end
  end
  return #entries > 0 and table.concat(entries, '\n') or '(not set)'
end

local TON = {
  [0] = 'unknown', [1] = 'international', [2] = 'national', [3] = 'network specific',
  [4] = 'subscriber', [5] = 'alphanumeric', [6] = 'abbreviated', [7] = 'reserved'
}
local NPI = {
  [0] = 'unknown', [1] = 'E.164', [3] = 'X.121', [4] = 'telex', [8] = 'national',
  [9] = 'private', [10] = 'ERMES', [15] = 'reserved'
}

local function decode_toa(value)
  if value == nil then return 'missing TOA' end
  return string.format('TON=%s, NPI=%s', TON[(value >> 4) & 7] or 'reserved',
    NPI[(value &  0x0F)] or 'reserved')
end

local function decode_dialled_number(toa, data)
  local ton = ((toa or 0x91) >> 4) & 7
  local digits = swap_bcd(data, true)
  if ton == 1 and not string.match(digits, '^%+') then digits = '+' .. digits end
  return digits
end

local function decode_adn(data)
  if #data < 14 then return 'Malformed ADN/MSISDN record: shorter than 14 bytes' end
  if all_ff(data) then return '(empty record)' end
  local alpha_length = #data - 14
  local alpha = decode_alpha(slice(data, 0, alpha_length - 1))
  local bcd_length = byte(data, alpha_length)
  local toa = byte(data, alpha_length + 1)
  if bcd_length == 0 or bcd_length == nil or toa == nil then return alpha .. ': malformed address length' end
  local number_length = math.max(0, math.min(10, bcd_length - 1))
  local number = decode_dialled_number(toa, slice(data, alpha_length + 2, alpha_length + 1 + number_length))
  local fields = {
    alpha ~= '' and ('Name: ' .. alpha) or 'Name: (none)',
    'Number: ' .. number,
    decode_toa(toa),
    'Capability/configuration record: ' .. tostring(byte(data, #data - 2)),
    'Extension record: ' .. tostring(byte(data, #data - 1))
  }
  if bcd_length - 1 > 10 then table.insert(fields, 'Warning: address length exceeds 10-byte field') end
  return table.concat(fields, '\n')
end

local function decode_spn(data)
  if #data == 0 or all_ff(data) then return '(not set)' end
  local flags = byte(data, 0)
  return string.format('Display flags: 0x%02X\nName: %s', flags, decode_alpha(slice(data, 1)))
end

local function decode_loci(data)
  if #data < 11 then return 'Malformed LOCI: expected at least 11 bytes' end
  local status_names = { [0] = 'updated', [1] = 'not updated', [2] = 'PLMN not allowed', [3] = 'location area not allowed' }
  return string.format('TMSI: %s\nLAI: %s, LAC=%s\nUpdate status: %s',
    hex(slice(data, 0, 3)), decode_plmn(slice(data, 4, 6)), hex(slice(data, 7, 8)),
    status_names[byte(data, 10)] or tostring(byte(data, 10)))
end

local function decode_psloci(data)
  if #data < 14 then return 'Malformed PSLOCI/LOCIGPRS: expected at least 14 bytes' end
  local status_names = { [0] = 'updated', [1] = 'not updated', [2] = 'PLMN not allowed', [3] = 'routing area not allowed' }
  return string.format('P-TMSI: %s\nP-TMSI signature: %s\nRAI: %s\nRA update status: %s',
    hex(slice(data, 0, 3)), hex(slice(data, 4, 6)), hex(slice(data, 7, 12)),
    status_names[byte(data, 13)] or tostring(byte(data, 13)))
end

local function decode_admin_data(data)
  if #data < 4 then return 'Malformed administrative data: expected at least 4 bytes' end
  local modes = {
    [0x00] = 'normal', [0x01] = 'normal + specific facilities', [0x02] = 'maintenance',
    [0x80] = 'type approval', [0x81] = 'type approval + specific facilities'
  }
  return string.format('UE operation mode: %s\nMNC length in IMSI: %d\nAdditional information: %s',
    modes[byte(data, 0)] or string.format('0x%02X', byte(data, 0)),
    (byte(data, 3) & 0x0F), hex(slice(data, 1, 2)))
end

local function decode_phase(data)
  local phases = { [1] = 'Phase 1', [2] = 'Phase 2', [3] = 'Phase 2+' }
  return phases[byte(data, 0)] or ('Unknown phase: ' .. tostring(byte(data, 0)))
end

local function decode_hpplmn(data)
  if #data == 0 then return '(not set)' end
  return string.format('Higher-priority PLMN search period: %d minute(s)', byte(data, 0))
end

local function decode_smss(data)
  if #data < 2 then return 'Malformed SMS status: expected at least 2 bytes' end
  return string.format('Last used TP-MR: %d\nMemory capacity exceeded: %s',
    byte(data, 0), (byte(data, 1) & 1) == 0 and 'yes' or 'no')
end

local function decode_ecc(data, meta)
  if all_ff(data) then return '(empty record)' end

  -- Some legacy SIMs expose EF.ECC as a transparent sequence of three-byte
  -- BCD codes, without the later per-record category and alpha fields.
  if meta and meta.format == 'gsm' and meta.structure == 'transparent' then
    local codes = {}
    for i = 0, #data - 1, 3 do
      local encoded = slice(data, i, i + 2)
      if #encoded < 3 then break end
      if not all_ff(encoded) then table.insert(codes, swap_bcd(encoded, true)) end
    end
    return #codes > 0 and ('Emergency codes (legacy transparent encoding): ' .. table.concat(codes, ', ')) or '(not set)'
  end

  if #data < 4 or all_ff(slice(data, 0, 2)) then return '(empty record)' end
  local categories = {}
  local flags = byte(data, #data - 1)
  local names = { 'police', 'ambulance', 'fire brigade', 'marine guard', 'mountain rescue', 'manual eCall', 'automatic eCall' }
  for i = 0, 6 do
    if (flags &  (1 <<  i)) ~= 0 then table.insert(categories, names[i + 1]) end
  end
  local alpha = #data > 4 and decode_alpha(slice(data, 3, #data - 2)) or ''
  return 'Emergency code: ' .. swap_bcd(slice(data, 0, 2), true) ..
    '\nCategory: ' .. (#categories > 0 and table.concat(categories, ', ') or 'none') ..
    (alpha ~= '' and ('\nName: ' .. alpha) or '')
end


local SST_NAMES = {
  'CHV1 disable function', 'Abbreviated Dialling Numbers', 'Fixed Dialling Numbers', 'Short Message Storage',
  'Advice of Charge', 'Capability Configuration Parameters', 'PLMN selector', 'RFU', 'MSISDN',
  'Extension1', 'Extension2', 'SMS Parameters', 'Last Number Dialled', 'Cell Broadcast Message Identifier',
  'Group Identifier Level 1', 'Group Identifier Level 2', 'Service Provider Name', 'Service Dialling Numbers',
  'Extension3', 'RFU', 'VGCS', 'VBS', 'enhanced Multi-Level Precedence and Pre-emption',
  'Automatic Answer for eMLPP', 'Data download via SMS-CB', 'Data download via SMS-PP', 'Menu selection',
  'Call control', 'Proactive SIM', 'Cell Broadcast Message Identifier Ranges', 'Barred Dialling Numbers',
  'Extension4', 'De-personalization Control Keys', 'Co-operative Network List', 'Short Message Status Reports',
  "Network's indication of alerting", 'MO-SMS control by SIM', 'GPRS', 'Image', 'SoLSA',
  'USSD string data object in Call Control', 'RUN AT COMMAND', 'User controlled PLMN selector with AcT',
  'Operator controlled PLMN selector with AcT', 'HPLMN selector with AcT', 'CPBCCH Information',
  'Investigation Scan', 'Extended Capability Configuration Parameters', 'MExE', 'Reserved',
  'PLMN Network Name', 'Operator PLMN List', 'Mailbox Dialling Numbers', 'Message Waiting Indication Status',
  'Call Forwarding Indication Status', 'Service Provider Display Information', 'Multimedia Messaging Service',
  'Extension 8', 'MMS User Connectivity Parameters'
}

local UST_NAMES = {
  [1] = 'Local Phone Book', [2] = 'Fixed Dialling Numbers', [3] = 'Extension 2',
  [4] = 'Service Dialling Numbers', [5] = 'Extension 3', [6] = 'Barred Dialling Numbers',
  [7] = 'Extension 4', [8] = 'Outgoing Call Information', [9] = 'Incoming Call Information',
  [10] = 'Short Message Storage', [11] = 'Short Message Status Reports', [12] = 'SMS Parameters',
  [13] = 'Advice of Charge', [14] = 'Capability Configuration Parameters 2',
  [15] = 'Cell Broadcast Message Identifier', [16] = 'Cell Broadcast Message Identifier Ranges',
  [17] = 'Group Identifier Level 1', [18] = 'Group Identifier Level 2', [19] = 'Service Provider Name',
  [20] = 'User controlled PLMN selector with AcT', [21] = 'MSISDN', [22] = 'Image',
  [27] = 'GSM Access', [28] = 'Data download via SMS-PP', [29] = 'Data download via SMS-CB',
  [30] = 'Call Control by USIM', [31] = 'MO-SMS Control by USIM', [32] = 'RUN AT COMMAND',
  [34] = 'Enabled Services Table', [35] = 'APN Control List', [36] = 'Depersonalisation Control Keys',
  [37] = 'Co-operative Network List', [38] = 'GSM security context', [39] = 'CPBCCH Information',
  [40] = 'Investigation Scan', [42] = 'Operator controlled PLMN selector with AcT',
  [43] = 'HPLMN selector with AcT', [44] = 'Extension 5', [45] = 'PLMN Network Name',
  [46] = 'Operator PLMN List', [47] = 'Mailbox Dialling Numbers', [48] = 'Message Waiting Indication Status',
  [49] = 'Call Forwarding Indication Status', [51] = 'Service Provider Display Information',
  [52] = 'Multimedia Messaging Service', [53] = 'Extension 8', [55] = 'MMS User Connectivity Parameters',
  [56] = "Network's indication of alerting", [57] = 'VGCS', [58] = 'VBS', [59] = 'Pseudonym',
  [66] = 'WLAN Reauthentication Identity', [68] = 'Generic Bootstrapping Architecture',
  [71] = 'Equivalent HPLMN', [73] = 'Equivalent HPLMN Presentation Indication',
  [74] = 'Last RPLMN Selection Indication', [78] = 'Service Provider Name Icon',
  [79] = 'PLMN Network Name Icon', [80] = 'Connectivity Parameters for USIM IP connections',
  [85] = 'EPS Mobility Management Information', [86] = 'Allowed CSG Lists', [89] = 'eCall Data',
  [95] = 'Support of UICC access to IMS', [96] = 'Non-Access Stratum configuration',
  [97] = 'PWS configuration', [99] = 'URI support by UICC', [100] = 'Extended EARFCN support',
  [101] = 'ProSe', [108] = 'ACDC', [115] = 'IMS configuration data',
  [120] = 'XCAP Configuration Data', [121] = 'EARFCN list for MTC/NB-IOT',
  [122] = '5GS Mobility Management Information', [123] = '5G Security Parameters',
  [124] = 'Subscription identifier privacy support', [125] = 'SUCI calculation by the USIM',
  [126] = 'UAC Access Identities', [129] = '5GS Operator PLMN List', [132] = 'Support for URSP',
  [137] = 'Pre-configured CAG information', [138] = 'SOR-CMCI storage',
  [140] = 'Storage of disaster roaming information', [141] = 'Pre-configured eDRX',
  [142] = '5G NSWO support', [144] = 'Higher Priority PLMN satellite search multiplier'
}

local EST_NAMES = { [1] = 'Fixed Dialling Numbers enabled', [2] = 'Barred Dialling Numbers enabled', [3] = 'APN Control List enabled' }

local function decode_gsm_service_table(data, names)
  local allocated, active = {}, {}
  local maximum = math.min(#data * 4, 255)
  for service = 1, maximum do
    local value = byte(data, math.floor((service - 1) / 4))
    local shift = ((service - 1) % 4) * 2
    local bits = (value >> shift) & 0x03
    local name = names[service] or string.format('Service %d', service)
    if (bits &  1) ~= 0 then table.insert(allocated, string.format('%d. %s', service, name)) end
    if (bits &  2) ~= 0 then table.insert(active, string.format('%d. %s', service, name)) end
  end
  return 'Available / allocated:\n' .. (#allocated > 0 and table.concat(allocated, '\n') or '(none)') ..
    '\n\nActivated / enabled:\n' .. (#active > 0 and table.concat(active, '\n') or '(none)')
end

local function decode_usim_service_table(data, names, heading)
  local available = {}
  local maximum = #data * 8
  for service = 1, maximum do
    local value = byte(data, math.floor((service - 1) / 8))
    local shift = 7 - ((service - 1) % 8)
    if ((value >> shift) & 1) ~= 0 then
      local name = names[service] or string.format('Service %d', service)
      table.insert(available, string.format('%d. %s', service, name))
    end
  end
  return heading .. ':\n' .. (#available > 0 and table.concat(available, '\n') or '(none)')
end

local function decode_sst(data) return decode_gsm_service_table(data, SST_NAMES) end
local function decode_ust(data) return decode_usim_service_table(data, UST_NAMES, 'Available') end
local function decode_est(data) return decode_usim_service_table(data, EST_NAMES, 'Enabled') end

local function decode_dir(data)
  local aids = {}
  collect_tlv_tag(data, 0x4F, aids)
  local labels = {}
  collect_tlv_tag(data, 0x50, labels)
  local lines = {}
  for i, aid in ipairs(aids) do
    local label = labels[i] and decode_alpha(labels[i]) or nil
    table.insert(lines, hex(aid) .. (label and label ~= '' and (' - ' .. label) or ''))
  end
  return #lines > 0 and table.concat(lines, '\n') or 'No application templates found'
end

---------------------------------------------------------------------------
-- SMS (ETSI TS 51.011 storage and 3GPP TS 23.040 TPDU) decoder
---------------------------------------------------------------------------

local function sms_status(value)
  if (value &  0x01) == 0 then return 'free space', 'empty' end
  local low3 = (value &  0x07)
  if low3 == 1 then return 'MT, message read', 'deliver' end
  if low3 == 3 then return 'MT, message to be read', 'deliver' end
  if low3 == 7 then return 'MO, message to be sent', 'submit' end
  local low5 = (value &  0x1F)
  if low5 == 0x05 then return 'MO, sent; status not requested', 'submit' end
  if low5 == 0x0D then return 'MO, sent; status requested but not received', 'submit' end
  if low5 == 0x15 then return 'MO, sent; status received but not stored', 'submit' end
  if low5 == 0x1D then return 'MO, sent; status received and stored', 'submit' end
  return 'RFU/unknown status', 'unknown'
end

local function decode_timestamp(data)
  if data == nil or #data < 7 then return 'malformed timestamp' end
  local function pair(pos)
    return swap_bcd(slice(data, pos, pos), false)
  end
  local year = tonumber(pair(0))
  local month, day = tonumber(pair(1)), tonumber(pair(2))
  local hour, minute, second = tonumber(pair(3)), tonumber(pair(4)), tonumber(pair(5))
  if not year or not month or not day or not hour or not minute or not second then return 'malformed timestamp' end
  year = year + (year >= 90 and 1900 or 2000)

  local tz_raw = byte(data, 6)
  local negative = (tz_raw &  0x08) ~= 0
  local tz_digits = swap_bcd(make_bytes((tz_raw &  0xF7)), false)
  local quarters = tonumber(tz_digits) or 0
  local sign = negative and '-' or '+'
  local zone = string.format('%s%02d:%02d', sign, math.floor(quarters / 4), (quarters % 4) * 15)
  return string.format('%04d-%02d-%02d %02d:%02d:%02d UTC%s', year, month, day, hour, minute, second, zone)
end

local function parse_tp_address(data, pos)
  local digits = byte(data, pos)
  local toa = byte(data, pos + 1)
  if digits == nil or toa == nil then return nil, pos, 'Truncated TP address' end
  local ton = (toa >> 4) & 7
  local octets = math.floor((digits + 1) / 2)
  if pos + 2 + octets > #data then return nil, pos, 'TP address exceeds record length' end
  local encoded = slice(data, pos + 2, pos + 1 + octets)
  local address
  if ton == 5 then
    address = decode_packed_gsm7(encoded, digits, 0)
  else
    address = decode_dialled_number(toa, encoded)
  end
  return { address = address, description = decode_toa(toa) }, pos + 2 + octets, nil
end

local function decode_dcs(dcs)
  local alphabet_names = { [0] = 'GSM 7-bit', [1] = '8-bit data', [2] = 'UCS2', [3] = 'reserved' }
  local alphabet = (dcs >> 2) & 0x03
  local compressed = false
  local details = {}
  if (dcs &  0xC0) == 0xF0 then
    alphabet = (dcs &  0x04) == 0 and 0 or 1
    table.insert(details, 'message class indication')
  else
    compressed = (dcs &  0x20) ~= 0
    if (dcs &  0x10) ~= 0 then table.insert(details, 'message class present') end
  end
  table.insert(details, alphabet_names[alphabet])
  if compressed then table.insert(details, 'compressed') end
  return alphabet, compressed, table.concat(details, ', ')
end

local function decode_udh(data)
  if #data == 0 then return nil, 0, 'UDHI set but user data is empty' end
  local declared = byte(data, 0) + 1
  if declared > #data then return nil, 0, 'UDH length exceeds user data' end
  local descriptions = {}
  local pos = 1
  while pos < declared do
    local iei, length = byte(data, pos), byte(data, pos + 1)
    if iei == nil or length == nil or pos + 1 + length >= declared then
      table.insert(descriptions, 'Malformed information element')
      break
    end
    local value = slice(data, pos + 2, pos + 1 + length)
    if iei == 0x00 and length == 3 then
      table.insert(descriptions, string.format('Concatenated SMS: reference %d, part %d/%d',
        byte(value, 0), byte(value, 2), byte(value, 1)))
    elseif iei == 0x08 and length == 4 then
      table.insert(descriptions, string.format('Concatenated SMS: reference %d, part %d/%d',
        byte(value, 0) * 256 + byte(value, 1), byte(value, 3), byte(value, 2)))
    elseif iei == 0x04 and length == 2 then
      table.insert(descriptions, string.format('Application port: destination %d, origin %d', byte(value, 0), byte(value, 1)))
    elseif iei == 0x05 and length == 4 then
      table.insert(descriptions, string.format('Application port: destination %d, origin %d',
        byte(value, 0) * 256 + byte(value, 1), byte(value, 2) * 256 + byte(value, 3)))
    else
      table.insert(descriptions, string.format('IEI %02X: %s', iei, hex(value)))
    end
    pos = pos + 2 + length
  end
  return table.concat(descriptions, '\n'), declared, nil
end

local function decode_user_data(record, udl_pos, dcs, udhi)
  local udl = byte(record, udl_pos)
  if udl == nil then return '', 'Missing TP-UDL', '', 'Truncated user data' end
  local start = udl_pos + 1
  local alphabet, compressed, encoding = decode_dcs(dcs)
  local ud = slice(record, start)
  local udh_text, udh_length, warning = '', 0, nil

  if udhi then
    udh_text, udh_length, warning = decode_udh(ud)
    if warning then return '', encoding, '', warning end
    udh_text = udh_text or ''
  end

  local text
  if compressed then
    text = '[Compressed user data not expanded]'
  elseif alphabet == 0 then
    local skip = math.ceil(udh_length * 8 / 7)
    text = decode_packed_gsm7(ud, udl, skip)
  elseif alphabet == 2 then
    text = decode_ucs2(slice(ud, udh_length, udh_length + udl - udh_length - 1))
  elseif alphabet == 1 then
    text = '[8-bit user data] ' .. hex(slice(ud, udh_length, udh_length + udl - udh_length - 1))
  else
    text = '[Reserved alphabet; raw user data] ' .. hex(ud)
  end
  return text, encoding, udh_text, nil
end

local function decode_sms(data)
  if #data == 0 then return 'Empty SMS record' end
  local status, direction = sms_status(byte(data, 0))
  if direction == 'empty' then return 'Status: ' .. status end
  local lines = { 'Status: ' .. status }
  local pos = 1
  local smsc_length = byte(data, pos)
  if smsc_length == nil then return table.concat(lines, '\n') .. '\nTruncated SMSC field' end
  if pos + 1 + smsc_length > #data then
    return table.concat(lines, '\n') .. '\nSMSC length exceeds record length'
  end
  if smsc_length > 0 then
    local toa = byte(data, pos + 1)
    table.insert(lines, 'SMSC: ' .. decode_dialled_number(toa, slice(data, pos + 2, pos + smsc_length)))
    table.insert(lines, 'SMSC address: ' .. decode_toa(toa))
  else
    table.insert(lines, 'SMSC: (not present)')
  end
  pos = pos + 1 + smsc_length

  local first = byte(data, pos)
  if first == nil then return table.concat(lines, '\n') .. '\nMissing TPDU first octet' end
  local udhi = (first &  0x40) ~= 0
  local dcs_pos, udl_pos

  if direction == 'deliver' then
    table.insert(lines, 'TPDU: SMS-DELIVER')
    local address, next_pos, err = parse_tp_address(data, pos + 1)
    if err then return table.concat(lines, '\n') .. '\n' .. err end
    table.insert(lines, 'Originating address: ' .. address.address)
    table.insert(lines, address.description)
    pos = next_pos
    if pos + 9 >= #data then return table.concat(lines, '\n') .. '\nTruncated SMS-DELIVER fields' end
    table.insert(lines, string.format('TP-PID: 0x%02X', byte(data, pos)))
    dcs_pos = pos + 1
    table.insert(lines, 'Service centre timestamp: ' .. decode_timestamp(slice(data, pos + 2, pos + 8)))
    udl_pos = pos + 9
  elseif direction == 'submit' then
    table.insert(lines, 'TPDU: SMS-SUBMIT')
    table.insert(lines, 'TP-MR: ' .. tostring(byte(data, pos + 1)))
    local address, next_pos, err = parse_tp_address(data, pos + 2)
    if err then return table.concat(lines, '\n') .. '\n' .. err end
    table.insert(lines, 'Destination address: ' .. address.address)
    table.insert(lines, address.description)
    pos = next_pos
    if pos + 1 >= #data then return table.concat(lines, '\n') .. '\nTruncated SMS-SUBMIT fields' end
    table.insert(lines, string.format('TP-PID: 0x%02X', byte(data, pos)))
    dcs_pos = pos + 1
    pos = pos + 2
    local vpf = (first &  0x18)
    local vp_octets = (vpf == 0x08 or vpf == 0x10) and 1 or (vpf == 0x18 and 7 or 0)
    if vp_octets > 0 then
      table.insert(lines, 'Validity period: ' .. hex(slice(data, pos, pos + vp_octets - 1)))
      pos = pos + vp_octets
    end
    udl_pos = pos
  else
    table.insert(lines, 'TPDU: direction unknown; remaining bytes preserved above')
    return table.concat(lines, '\n')
  end

  local dcs = byte(data, dcs_pos)
  if dcs == nil or udl_pos >= #data then return table.concat(lines, '\n') .. '\nMissing TP-DCS or TP-UDL' end
  local text, encoding, udh, warning = decode_user_data(data, udl_pos, dcs, udhi)
  table.insert(lines, string.format('TP-DCS: 0x%02X (%s)', dcs, encoding))
  table.insert(lines, 'TP-UDL: ' .. tostring(byte(data, udl_pos)))
  if udh ~= '' then table.insert(lines, 'User data header:\n' .. udh) end
  if warning then table.insert(lines, 'Decode warning: ' .. warning) end
  table.insert(lines, 'Text:\n' .. text)
  return table.concat(lines, '\n')
end


---------------------------------------------------------------------------
-- Filesystem map. Unknown files remain visible as raw bytes when selected.
---------------------------------------------------------------------------

local function ef(fid, label, decoder, sensitive)
  return { kind = 'file', fid = fid, label = label, decode = decoder, sensitive = sensitive }
end

local function df(fid, label, children)
  return { kind = 'df', fid = fid, label = label, children = children }
end

local TELECOM_CHILDREN = {
  ef('6F06', 'Access rule reference'),
  ef('6F3A', 'Abbreviated dialling numbers (ADN)', decode_adn),
  ef('6F3B', 'Fixed dialling numbers (FDN)', decode_adn),
  ef('6F3C', 'Short messages (SMS)', decode_sms),
  ef('6F3D', 'Capability configuration parameters'),
  ef('6F40', 'MSISDN', decode_adn),
  ef('6F42', 'SMS parameters'),
  ef('6F43', 'SMS status', decode_smss),
  ef('6F44', 'Last number dialled (LND)', decode_adn),
  ef('6F47', 'Short message status reports'),
  ef('6F49', 'Service dialling numbers (SDN)', decode_adn),
  ef('6F4A', 'Extension 1'), ef('6F4B', 'Extension 2'), ef('6F4C', 'Extension 3'),
  ef('6F4D', 'Barred dialling numbers (BDN)', decode_adn),
  ef('6F4E', 'Extension 4'), ef('6F4F', 'Extended capability configuration parameters'),
  ef('6F54', 'SetUp menu elements'), ef('6F58', 'Comparison method information'),
  df('5F3A', 'Phone book', {
    ef('4F30', 'Phone book reference file'), ef('4F22', 'Phone book synchronization counter'),
    ef('4F23', 'Change counter'), ef('4F24', 'Previous unique identifier')
  })
}

local GSM_CHILDREN = {
  ef('6F05', 'Language preference', decode_lp),
  ef('6F07', 'IMSI', decode_imsi),
  ef('6F20', 'Ciphering key Kc', nil, true),
  ef('6F30', 'PLMN selector', decode_plmn_list),
  ef('6F31', 'Higher-priority PLMN search period', decode_hpplmn),
  ef('6F37', 'ACM maximum value'), ef('6F38', 'SIM service table (SST)', decode_sst),
  ef('6F39', 'Accumulated call meter'), ef('6F3E', 'Group identifier level 1'),
  ef('6F3F', 'Group identifier level 2'), ef('6F41', 'Price per unit and currency table'),
  ef('6F45', 'Cell broadcast message identifiers'), ef('6F46', 'Service provider name (SPN)', decode_spn),
  ef('6F52', 'GPRS ciphering key KcGPRS', nil, true),
  ef('6F53', 'GPRS location information', decode_psloci),
  ef('6F60', 'User controlled PLMN selector with AcT', decode_plmn_act),
  ef('6F61', 'Operator controlled PLMN selector with AcT', decode_plmn_act),
  ef('6F62', 'HPLMN selector with AcT', decode_plmn_act),
  ef('6F74', 'Broadcast control channels'), ef('6F78', 'Access control class'),
  ef('6F7B', 'Forbidden PLMNs', decode_plmn_list), ef('6F7E', 'Location information', decode_loci),
  ef('6FAD', 'Administrative data', decode_admin_data), ef('6FAE', 'Phase identification', decode_phase),
  ef('6FB7', 'Emergency call codes', decode_ecc),
  ef('6FC5', 'PLMN network name'), ef('6FC6', 'Operator PLMN list'),
  ef('6FC7', 'Mailbox dialling numbers', decode_adn), ef('6FC9', 'Mailbox identifier'),
  ef('6FCA', 'Message waiting indication status'), ef('6FCB', 'Call forwarding indication status')
}

local USIM_CHILDREN = {
  ef('6F05', 'Language indication', decode_languages), ef('6F06', 'Access rule reference'),
  ef('6F07', 'IMSI', decode_imsi),
  ef('6F08', 'Ciphering and integrity keys', nil, true),
  ef('6F09', 'PS ciphering and integrity keys', nil, true),
  ef('6F2C', 'Depersonalisation control keys', nil, true),
  ef('6F31', 'Higher-priority PLMN search period', decode_hpplmn),
  ef('6F37', 'ACM maximum value'), ef('6F38', 'USIM service table (UST)', decode_ust),
  ef('6F39', 'Accumulated call meter'), ef('6F3B', 'Fixed dialling numbers (FDN)', decode_adn),
  ef('6F3C', 'Short messages (SMS)', decode_sms), ef('6F3E', 'Group identifier level 1'),
  ef('6F3F', 'Group identifier level 2'), ef('6F40', 'MSISDN', decode_adn),
  ef('6F41', 'Price per unit and currency table'), ef('6F42', 'SMS parameters'),
  ef('6F43', 'SMS status', decode_smss), ef('6F45', 'Cell broadcast message identifiers'),
  ef('6F46', 'Service provider name (SPN)', decode_spn), ef('6F47', 'Short message status reports'),
  ef('6F48', 'Cell broadcast message identifier ranges'), ef('6F49', 'Service dialling numbers (SDN)', decode_adn),
  ef('6F4B', 'Extension 2'), ef('6F4C', 'Extension 3'), ef('6F4D', 'Barred dialling numbers', decode_adn),
  ef('6F4E', 'Extension 5'), ef('6F4F', 'Capability configuration parameters 2'),
  ef('6F56', 'Enabled services table (EST)', decode_est),
  ef('6F60', 'User controlled PLMN selector with AcT', decode_plmn_act),
  ef('6F61', 'Operator controlled PLMN selector with AcT', decode_plmn_act),
  ef('6F62', 'HPLMN selector with AcT', decode_plmn_act),
  ef('6F73', 'Packet-switched location information', decode_psloci),
  ef('6F78', 'Access control class'), ef('6F7B', 'Forbidden PLMNs', decode_plmn_list),
  ef('6F7E', 'Location information', decode_loci), ef('6FAD', 'Administrative data', decode_admin_data),
  ef('6FB7', 'Emergency call codes', decode_ecc), ef('6FC5', 'PLMN network name'),
  ef('6FC6', 'Operator PLMN list'), ef('6FC7', 'Mailbox dialling numbers', decode_adn),
  ef('6FC9', 'Mailbox identifier'), ef('6FCA', 'Message waiting indication status'),
  ef('6FCB', 'Call forwarding indication status'), ef('6FCD', 'Service provider display information'),
  ef('6FD9', 'Equivalent HPLMN', decode_plmn_list), ef('6FDB', 'Equivalent HPLMN presentation indication'),
  ef('6FE3', 'EPS location information'), ef('6FE4', 'EPS NAS security context', nil, true),
  ef('6FE8', 'Non-Access Stratum configuration'),
  df('5F3A', 'Phone book', {
    ef('4F30', 'Phone book reference file'), ef('4F22', 'Phone book synchronization counter'),
    ef('4F23', 'Change counter'), ef('4F24', 'Previous unique identifier')
  }),
  df('5FC0', '5GS', {
    ef('4F01', '5GS 3GPP location information'), ef('4F02', '5GS non-3GPP location information'),
    ef('4F03', '5GS 3GPP NAS security context', nil, true),
    ef('4F04', '5GS non-3GPP NAS security context', nil, true),
    ef('4F05', '5G authentication keys', nil, true), ef('4F06', 'UAC Access Identities'),
    ef('4F07', 'SUCI calculation information'), ef('4F08', '5GS operator PLMN list'),
    ef('4F09', 'SUPI as Network Access Identifier'), ef('4F0A', 'Routing indicator'),
    ef('4F0B', 'UE Route Selector Policies')
  })
}

local MF_CHILDREN = {
  ef('2F00', 'Application directory (EF_DIR)', decode_dir),
  ef('2F05', 'Preferred languages', decode_languages),
  ef('2F06', 'Access rule reference'), ef('2FE2', 'ICCID', decode_iccid),
  df('7F10', 'DF.TELECOM', TELECOM_CHILDREN),
  df('7F20', 'DF.GSM', GSM_CHILDREN)
}

---------------------------------------------------------------------------
-- Filesystem traversal and per-record error isolation
---------------------------------------------------------------------------

local function decode_content(node, data, spec, meta)
  if not spec.decode then return end
  local ok, result = pcall(spec.decode, data, meta)
  if ok and result ~= nil then
    set_alt(node, result)
  else
    STATS.parse_errors = STATS.parse_errors + 1
    append(node, 'item', 'Decoder warning', tostring(result))
  end
end

local function report_read_error(node, sw)
  STATS.read_errors = STATS.read_errors + 1
  if is_access_denied(sw) then STATS.denied = STATS.denied + 1 end
  append(node, 'item', 'Read failed', sw_text(sw))
end

local function read_transparent(session, node, spec, meta)
  local remaining = meta.file_size
  if remaining == nil then
    append(node, 'item', 'Content not read', 'File size is unavailable in SELECT response')
    return
  end
  if remaining == 0 then
    append(node, 'body', 'Data (empty file)', empty_bytes(), '(empty)')
    return
  end

  local offset = 0
  local content = empty_bytes()
  while offset < remaining do
    local amount = math.min(CONFIG.transparent_chunk, remaining - offset)
    local sw, data = read_binary(session, offset, amount)
    if is_access_denied(sw) and offer_verification(session) then sw, data = read_binary(session, offset, amount) end
    if sw ~= 0x9000 then
      report_read_error(node, sw)
      return
    end
    content = concat_data(content, data)
    if #data < amount then
      append(node, 'item', 'Short read warning', string.format('Requested %d byte(s), received %d', amount, #data))
      break
    end
    offset = offset + amount
  end

  local body = append(node, 'body', 'Data', content)
  decode_content(body, content, spec, meta)
  if spec.fid == '2F00' then session.dir_data = session.dir_data or {}; table.insert(session.dir_data, content) end
end

local function read_records(session, node, spec, meta)
  local length = meta.record_length
  local count = meta.record_count
  if length == nil or length <= 0 then
    append(node, 'item', 'Content not read', 'Record length is missing or zero')
    return
  end
  if count == nil or count == 0 then
    if meta.file_size then count = math.floor(meta.file_size / length) else count = 0 end
  end
  if count > CONFIG.max_records then
    append(node, 'item', 'Record limit warning', string.format('Reading only %d of %d records', CONFIG.max_records, count))
    count = CONFIG.max_records
  end

  for record_number = 1, count do
    local sw, data = read_record(session, record_number, length)
    if is_access_denied(sw) and offer_verification(session) then
      sw, data = read_record(session, record_number, length)
    end
    if sw ~= 0x9000 then
      report_read_error(node, sw)
      return
    end
    STATS.records = STATS.records + 1
    local record = append(node, 'record', 'Record ' .. record_number, data, nil, record_number)
    decode_content(record, data, spec, meta)
    if spec.fid == '2F00' then session.dir_data = session.dir_data or {}; table.insert(session.dir_data, data) end
  end
end

-- Rebuild the current DF path from the MF or ADF root. Selecting a DF's own
-- FID from inside itself is not portable, especially after a nested DF scan.
local function restore_path(session)
  local sw
  if session.root_kind == 'application' then
    sw = select_file(session, session.root_fid, 'application')
  else
    sw = select_file(session, '3F00', 'df')
  end
  if sw ~= 0x9000 then return sw end
  for _, fid in ipairs(session.path or {}) do
    sw = select_file(session, fid, 'df')
    if sw ~= 0x9000 then return sw end
  end
  return 0x9000
end

local function scan_entry(session, parent_node, spec)
  local sw, response = select_file(session, spec.fid, spec.kind)
  if is_access_denied(sw) and offer_verification(session) then
    sw, response = select_file(session, spec.fid, spec.kind)
  end
  if sw ~= 0x9000 then
    if is_missing(sw) then
      STATS.missing = STATS.missing + 1
    else
      STATS.read_errors = STATS.read_errors + 1
      if is_access_denied(sw) then STATS.denied = STATS.denied + 1 end
      append(parent_node, spec.kind == 'df' and 'folder' or 'file', spec.label .. ' [' .. spec.fid .. ']',
        'SELECT failed: ' .. sw_text(sw), nil, spec.fid)
    end
    return nil, false
  end

  STATS.files = STATS.files + 1
  local classname = spec.kind == 'df' and 'folder' or (spec.kind == 'application' and 'application' or 'file')
  local node = append(parent_node, classname, spec.label .. ' [' .. spec.fid .. ']', nil, nil, spec.fid)
  local meta = parse_metadata(response)
  append_metadata(node, response, meta)

  if spec.kind == 'df' or spec.kind == 'application' then
    session.path = session.path or {}
    table.insert(session.path, spec.fid)
    for _, child in ipairs(spec.children or {}) do
      scan_entry(session, node, child)
      if child.kind == 'df' then
        local restore_sw = restore_path(session)
        if restore_sw ~= 0x9000 then
          append(node, 'item', 'Navigation warning', 'Could not restore parent DF: ' .. sw_text(restore_sw))
          break
        end
      end
    end
    table.remove(session.path)
  elseif spec.sensitive then
    STATS.sensitive_skipped = STATS.sensitive_skipped + 1
    append(node, 'item', 'Sensitive content not read', 'Key material is never read by this analyser')
  elseif meta.structure == 'transparent' then
    read_transparent(session, node, spec, meta)
  elseif meta.structure == 'linear fixed' or meta.structure == 'cyclic' then
    read_records(session, node, spec, meta)
  else
    append(node, 'item', 'Content not read', 'Unknown or unsupported file structure: ' .. tostring(meta.structure))
  end
  return node, true
end

local function discover_usim_aids(session)
  local aids, seen = {}, {}
  for _, record in ipairs(session.dir_data or {}) do
    local found = {}
    collect_tlv_tag(record, 0x4F, found)
    for _, aid in ipairs(found) do
      local value = hex(aid)
      if string.sub(value, 1, 14) == 'A0000000871002' and not seen[value] then
        seen[value] = true
        table.insert(aids, value)
      end
    end
  end
  if #aids == 0 then
    table.insert(aids, 'A0000000871002FFFFFFFF8907090000')
  end
  return aids
end

local function append_summary(root, detected)
  local text = string.format(
    'Profiles detected: %s\nFiles selected: %d\nRecords read: %d\nAbsent files: %d\nAccess-denied operations: %d\nOther read/select errors: %d\nDecoder errors: %d\nSensitive files not read: %d',
    detected, STATS.files, STATS.records, STATS.missing, STATS.denied,
    STATS.read_errors - STATS.denied, STATS.parse_errors, STATS.sensitive_skipped)
  append(root, 'block', 'Analysis summary', text)
end

local function run_analysis()
  local root = cardpeek.nodes.root():append('telecom', 'GSM SIM + USIM')
  local detected = {}

  -- Try the legacy GSM class first, then the standard UICC class.
  local mf_session = {
    cla = 0xA0, legacy = true, dir_data = {}
  }
  local sw, response = select_file(mf_session, '3F00', 'df')
  if sw ~= 0x9000 or parse_metadata(response).format == 'fcp' then
    -- A UICC may answer class A0 for compatibility, but its normal file
    -- commands and EF-under-DF selections use class 00.
    mf_session = { cla = 0x00, legacy = false, dir_data = {} }
    sw, response = select_file(mf_session, '3F00', 'df')
  else
    mf_session.legacy = true
  end

  if sw ~= 0x9000 then
    append(root, 'item', 'Master File selection failed', sw_text(sw))
    append_summary(root, 'none')
    return
  end

  mf_session.root_kind = 'df'
  mf_session.root_fid = '3F00'
  mf_session.path = {}
  local mf_spec = { kind = 'df', fid = '3F00', label = 'Master File', children = MF_CHILDREN }
  local mf_node = append(root, 'folder', 'Master File [3F00]', nil, nil, '3F00')
  append_metadata(mf_node, response, parse_metadata(response))
  for _, child in ipairs(MF_CHILDREN) do
    scan_entry(mf_session, mf_node, child)
    if child.kind == 'df' then
      local restore_sw = restore_path(mf_session)
      if restore_sw ~= 0x9000 then
        append(mf_node, 'item', 'Navigation warning', 'Could not restore MF: ' .. sw_text(restore_sw))
        break
      end
    end
  end

  local mf_meta = parse_metadata(response)
  if mf_meta.format == 'gsm' then table.insert(detected, 'classic GSM') end
  -- DF.GSM presence is determined by a fresh, harmless SELECT.
  local gsm_probe = select_file(mf_session, '7F20', 'df')
  if gsm_probe == 0x9000 and not mf_session.legacy then table.insert(detected, 'GSM application on UICC') end
  select_file(mf_session, '3F00', 'df')

  for _, aid in ipairs(discover_usim_aids(mf_session)) do
    local usim = { cla = 0x00, legacy = false, dir_data = {} }
    local usw, uresponse = select_file(usim, aid, 'application')
    local legacy_usim = false
    local legacy_without_le = false
    if usw == 0x6E00 or usw == 0x6B00 then
      -- Some legacy USIM implementations reject logical-channel class 00
      -- but accept the same AID selection and filesystem commands class A0.
      usim = { cla = 0xA0, legacy = true, dir_data = {} }
      usw, uresponse = select_file(usim, aid, 'application')
      if usw == 0x6B00 then
        -- Legacy T=0 SELECT is a case-3 command on some cards: the trailing
        -- Le byte is rejected even though the same CLA and AID are accepted.
        usw, uresponse = select_file(usim, aid, 'application', true)
        legacy_without_le = usw == 0x9000
        usim.application_without_le = legacy_without_le
      end
      legacy_usim = usw == 0x9000
    end
    if usw == 0x9000 then
      table.insert(detected, 'USIM ' .. aid .. (legacy_usim and ' (class A0 compatibility)' or ''))
      local app_spec = { kind = 'application', fid = aid, label = 'ADF.USIM', children = USIM_CHILDREN }
      local app_node = append(root, 'application', 'ADF.USIM [' .. aid .. ']', nil, nil, aid)
      if legacy_usim then
        append(app_node, 'item', 'Compatibility mode', 'Class 00 was rejected; ADF.USIM was selected with class A0' ..
          (legacy_without_le and ' and without an Le byte' or ''))
      end
      append_metadata(app_node, uresponse, parse_metadata(uresponse))
      usim.root_kind = 'application'
      usim.root_fid = aid
      usim.path = {}
      for _, child in ipairs(USIM_CHILDREN) do
        scan_entry(usim, app_node, child)
        if child.kind == 'df' then
          local restore_sw = restore_path(usim)
          if restore_sw ~= 0x9000 then
            append(app_node, 'item', 'Navigation warning', 'Could not restore ADF.USIM: ' .. sw_text(restore_sw))
            break
          end
        end
      end
    elseif not is_missing(usw) then
      append(root, 'item', 'USIM selection failed', aid .. ': ' .. sw_text(usw))
    end
  end

  if #detected == 0 then table.insert(detected, 'UICC / unidentified telecom profile') end
  append_summary(root, table.concat(detected, '; '))
  cardpeek.log.info(string.format('Selected %d files and read %d records', STATS.files, STATS.records))
end

run_analysis()
