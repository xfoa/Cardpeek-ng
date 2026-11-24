local cp = require('cardpeek')

local M = {}

function M.transmit(command)
  local response, failure = cp.card.transmit(command)
  if failure then error(failure.message) end
  return response
end

function M.select(path, return_what, length, cla)
  local file_id, selection = M.file_path(path)
  if file_id == nil then return { status = 0x6F00, data = cp.bytes.pack(8) } end
  local command = cp.bytes.pack(8, cla or 0x00, 0xA4, selection, return_what or 0,
    #file_id, file_id, length == nil and 0 or length)
  return M.transmit(command)
end

function M.file_path(path)
  if type(path) == 'userdata' then return path, 0 end
  path = path or ''
  local prefix, value = path:sub(1, 1), path:sub(2)
  if prefix == '#' then
    return cp.bytes.pack(8, value), #value == 4 and 0 or 4
  elseif prefix == '.' and value:match('^%x%x%x%x$') then
    return cp.bytes.pack(8, value), 2
  elseif prefix == '.' and value:match('^%x%x%x%x/$') then
    return cp.bytes.pack(8, value:sub(1, 4)), 1
  elseif path == '..' then
    return cp.bytes.pack(8), 3
  elseif path:sub(1, 2) == './' then
    return cp.bytes.pack(8, path:sub(3)), 9
  elseif prefix == '/' then
    local cleaned = path:gsub('/', '')
    return cp.bytes.pack(8, cleaned), 8
  end
  return nil, nil
end

function M.read_record(sfi, record, length, cla)
  sfi = sfi == '.' and 0 or (sfi or 0)
  return M.transmit(cp.bytes.pack(8, cla or 0, 0xB2, record, (sfi << 3) | 4, length or 0))
end

function M.read_binary(offset, length, cla)
  return M.transmit(cp.bytes.pack(8, cla or 0, 0xB0, ((offset or 0) >> 8) & 0x7F,
    (offset or 0) & 0xFF, length or 0))
end

function M.get_data(tag, length, cla)
  return M.transmit(cp.bytes.pack(8, cla or 0, 0xCA, (tag >> 8) & 0xFF, tag & 0xFF, length or 0))
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
