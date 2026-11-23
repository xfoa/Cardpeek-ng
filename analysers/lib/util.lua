local cp = require('cardpeek')

local M = {}

function M.bytes(width, ...)
  local values = {}
  local arguments = table.pack(...)
  for index = 1, arguments.n do
    local value = arguments[index]
    if type(value) == 'string' then
      local parsed = cp.bytes.from_hex(value, width)
      for item in parsed:iter() do table.insert(values, item) end
    elseif type(value) == 'userdata' then
      assert(value:width() == width, 'byte string widths differ')
      for item in value:iter() do table.insert(values, item) end
    else
      table.insert(values, value)
    end
  end
  return cp.bytes.new(width, values)
end

function M.get(data, index)
  if data == nil or index < 0 or index >= #data then return nil end
  return data[index + 1]
end

function M.sub(data, first, last)
  if data == nil then return nil end
  local size = #data
  first = first or 0
  last = last or (size - 1)
  if first < 0 then first = size + first end
  if last < 0 then last = size + last end
  if first < 0 or last < first or first >= size then return nil end
  last = math.min(last, size - 1)
  return data:slice(first + 1, last - first + 1)
end

function M.concat(...)
  local result
  local arguments = table.pack(...)
  for index = 1, arguments.n do
    local value = arguments[index]
    if type(value) ~= 'userdata' then value = M.bytes(8, value) end
    if result == nil then result = value else result = result .. value end
  end
  return result or M.bytes(8)
end

function M.number(data)
  local result = 0
  if data == nil then return result end
  local coefficient = 2 ^ data:width()
  for value in data:iter() do result = result * coefficient + value end
  return result
end

function M.format(data, format)
  local result = {}
  local index = 1
  while index <= #format do
    local char = format:sub(index, index)
    if char ~= '%' then
      table.insert(result, char)
    else
      index = index + 1
      local code = format:sub(index, index)
      if code == '%' then
        table.insert(result, '%')
      elseif code == 'D' then
        table.insert(result, data:to_hex())
      elseif code == 'S' then
        table.insert(result, tostring(data:width()) .. ':' .. data:to_hex())
      elseif code == 'w' then
        table.insert(result, tostring(data:width()))
      elseif code == 'l' then
        table.insert(result, tostring(#data))
      elseif code == 'I' then
        table.insert(result, string.format('%.0f', M.number(data)))
      elseif code == 'C' then
        for value in data:iter() do table.insert(result, string.char(value)) end
      elseif code == 'P' then
        for value in data:iter() do
          table.insert(result, value >= 32 and value < 127 and string.char(value) or '.')
        end
      else
        error('unsupported byte format %' .. code)
      end
    end
    index = index + 1
  end
  return table.concat(result)
end

function M.printable(data)
  if data == nil or #data == 0 then return false end
  for value in data:iter() do
    if value < 32 or value >= 127 then return false end
  end
  return true
end

function M.reverse(data)
  local values = data:elements()
  local reversed = {}
  for index = #values, 1, -1 do table.insert(reversed, values[index]) end
  return cp.bytes.new(data:width(), reversed)
end

function M.pad_left(data, length, value)
  local values = data:elements()
  while #values < length do table.insert(values, 1, value) end
  return cp.bytes.new(data:width(), values)
end

function M.pad_right(data, length, value)
  local values = data:elements()
  while #values < length do table.insert(values, value) end
  return cp.bytes.new(data:width(), values)
end

function M.transmit(command)
  local response, failure = cp.card.transmit(command)
  if failure then error(failure.message) end
  return response
end

function M.select(path, return_what, length, cla)
  local file_id, selection = M.file_path(path)
  if file_id == nil then return { status = 0x6F00, data = M.bytes(8) } end
  local command = M.bytes(8, cla or 0x00, 0xA4, selection, return_what or 0,
    #file_id, file_id, length == nil and 0 or length)
  return M.transmit(command)
end

function M.file_path(path)
  if type(path) == 'userdata' then return path, 0 end
  path = path or ''
  local prefix, value = path:sub(1, 1), path:sub(2)
  if prefix == '#' then
    return M.bytes(8, value), #value == 4 and 0 or 4
  elseif prefix == '.' and value:match('^%x%x%x%x$') then
    return M.bytes(8, value), 2
  elseif prefix == '.' and value:match('^%x%x%x%x/$') then
    return M.bytes(8, value:sub(1, 4)), 1
  elseif path == '..' then
    return M.bytes(8), 3
  elseif path:sub(1, 2) == './' then
    return M.bytes(8, path:sub(3)), 9
  elseif prefix == '/' then
    local cleaned = path:gsub('/', '')
    return M.bytes(8, cleaned), 8
  end
  return nil, nil
end

function M.read_record(sfi, record, length, cla)
  sfi = sfi == '.' and 0 or (sfi or 0)
  return M.transmit(M.bytes(8, cla or 0, 0xB2, record, (sfi << 3) | 4, length or 0))
end

function M.read_binary(offset, length, cla)
  return M.transmit(M.bytes(8, cla or 0, 0xB0, ((offset or 0) >> 8) & 0x7F,
    (offset or 0) & 0xFF, length or 0))
end

function M.get_data(tag, length, cla)
  return M.transmit(M.bytes(8, cla or 0, 0xCA, (tag >> 8) & 0xFF, tag & 0xFF, length or 0))
end

function M.node(parent, class, label, value, alternative, identifier)
  local node = parent:append(class or 'item', label or '')
  if value ~= nil then
    if type(value) == 'userdata' then node:set('value', value)
    else node:set('value', tostring(value)) end
  end
  if alternative ~= nil then node:set('alternative', tostring(alternative)) end
  if identifier ~= nil then node:set('identifier', tostring(identifier)) end
  return node
end

function M.success(response)
  return response.status == 0x9000
end

return M
