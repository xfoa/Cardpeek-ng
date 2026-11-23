local cp = require('cardpeek')
local util = require('shared.lib.util')
local country = require('shared.lib.country-codes')
local networks = require('shared.lib.network-codes')

local M = {}
local EPOCH = os.time({ hour = 0, min = 0, year = 1997, month = 1, sec = 0, day = 1 })
local TIMEZONE_DELAY = EPOCH - 852076800

M.BITMAP = 1
M.REPEAT = 2
M.BITMAP_BE = 3

function M.date(source, reference)
  reference = reference or EPOCH
  local seconds = reference < 0 and (-reference) - util.number(source) * 86400
    or reference + util.number(source) * 86400
  return os.date('%a %x', seconds)
end

function M.time(source)
  local value = util.pad_left(util.sub(source, 0, 10), 32, 0)
  return os.date('%H:%M', TIMEZONE_DELAY + util.number(value) * 60)
end

function M.quarters(source)
  local value = util.pad_left(util.sub(source, 0, 6), 32, 0)
  local number = util.number(value)
  if number == 96 then return 'End of service' end
  if number == 127 then return 'Not significant' end
  return os.date('%H:%M', TIMEZONE_DELAY + number * 900)
end

function M.date_time(source, reference)
  reference = reference or EPOCH
  local seconds = reference < 0 and (-reference) - util.number(source)
    or reference + util.number(source)
  return os.date('%c', seconds)
end

function M.bcd_date(source)
  local value = source:convert(8):to_hex()
  return value:sub(7, 8) .. '/' .. value:sub(5, 6) .. '/' .. value:sub(1, 4)
end

local ALPHA = { '-', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '?', '?', '?', '?', ' ' }

function M.alpha(source)
  local output = {}
  for index = 0, #source - 4, 5 do
    table.insert(output, ALPHA[util.number(util.sub(source, index, index + 4)) + 1])
  end
  return table.concat(output)
end

function M.network_id(source)
  local country_code = tonumber(util.sub(source, 0, 11):convert(4):to_hex())
  local region_code = tonumber(util.sub(source, 12, 23):convert(4):to_hex())
  local result = 'country ' .. country.name(country_code)
  if region_code then result = result .. ' / network ' .. networks.name(country_code, region_code) end
  return result
end

function M.number(source) return util.number(source) end
function M.amount(source) return string.format('%.2f EUR', util.number(source) / 100) end

function M.zones(source)
  local value = util.number(source)
  local maximum, minimum = 0, nil
  for zone = 8, 1, -1 do
    local bit = 2 ^ (zone - 1)
    if value >= bit then
      if maximum == 0 then maximum = zone end
      value = value - bit
      if value == 0 then minimum = zone end
    end
  end
  return string.format('%s-%d', tostring(minimum), maximum)
end

function M.undefined(source) return '0x' .. source:convert(8):to_hex() end

local function split_bitmap(table_value, bitmap_size)
  local keys = {}
  for key in pairs(table_value) do table.insert(keys, key) end
  table.sort(keys)
  local head, bitmap = {}, {}
  local head_size = math.max(0, #keys - bitmap_size)
  for index, key in ipairs(keys) do
    if index <= head_size then head[index] = table_value[key]
    else bitmap[index - head_size - 1] = table_value[key] end
  end
  return head, bitmap
end

local parse_item

parse_item = function(parent, format, data, position)
  if format == nil then return 0 end
  local parsed = format[2]
  local item = util.sub(data, position, position + parsed - 1)
  local node = util.node(parent, 'item', format[3])

  if format[1] == M.BITMAP or format[1] == M.BITMAP_BE then
    if parsed > 0 then
      if item == nil then
        node:remove()
        cp.log.warning('Missing non-empty bitmap ' .. format[3])
        return 0
      end
      util.node(node, 'item', '(' .. format[3] .. 'Bitmap)', item)
      local head, bitmap = split_bitmap(format[4], parsed)
      for _, sub in pairs(head) do parsed = parsed + parse_item(node, sub, data, position + parsed) end
      local ordered = format[1] == M.BITMAP and util.reverse(item) or item
      for index, bit in ordered:ipairs() do
        if bit == 1 then parsed = parsed + parse_item(node, bitmap[index], data, position + parsed) end
      end
    else
      for _, sub in pairs(format[4]) do parsed = parsed + parse_item(node, sub, data, position + parsed) end
    end
  elseif format[1] == M.REPEAT then
    if item == nil then
      node:remove()
      cp.log.warning('Missing repeat entry ' .. format[3])
      return 0
    end
    node:set('value', item)
    node:set('alternative', string.format('%.0f', util.number(item)))
    for _ = 1, util.number(item) do
      parsed = parsed + parse_item(node, format[4][0], data, position + parsed)
    end
  else
    if item == nil then
      node:remove()
      cp.log.warning('Missing entry ' .. format[3])
      return 0
    end
    local alternative
    if type(format[4]) == 'table' then alternative = format[1](item, table.unpack(format[4]))
    elseif format[4] ~= nil then alternative = format[1](item, format[4])
    else alternative = format[1](item) end
    if alternative == nil then node:remove()
    else
      node:set('value', item)
      node:set('alternative', tostring(alternative))
    end
  end
  return parsed
end

local function parse(parent, format, data)
  local parsed = 0
  for index = 0, #format do parsed = parsed + parse_item(parent, format[index], data, parsed) end
  return parsed
end

function M.map(root, condition, ...)
  local file_condition, record_condition
  if type(condition) == 'string' then
    file_condition, record_condition = { label = condition }, { label = 'record' }
  else
    file_condition, record_condition = condition.file, condition.record
  end
  for file in cp.nodes.find(root, file_condition) do
    for record in cp.nodes.find(file, record_condition) do
      local bits = record:get('value'):convert(1)
      local parsed = 0
      for _, template in ipairs({ ... }) do
        local block = util.sub(bits, parsed)
        if block and not cp.bytes.all(block, 0) then parsed = parsed + parse(record, template, block) end
      end
      local remaining = util.sub(bits, parsed)
      if remaining and util.number(remaining) > 0 then
        util.node(record, 'item', '(remaining unparsed data)', remaining, '(binary data)')
      end
    end
  end
end

function M.is_all(data, value)
  return cp.bytes.all(data, value)
end

return M
