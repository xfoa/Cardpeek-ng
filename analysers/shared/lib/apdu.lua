local cp = require('cardpeek')
local util = require('shared.lib.util')

local M = {}

function M.start(title)
  local atr, failure = cp.card.atr()
  if failure then error(failure.message) end
  local root = cp.nodes.root():append('card', title)
  local node = root:append('atr', 'cold ATR')
  node:set('value', atr.bytes)
  if atr.record then node:set_provenance(atr.record, 'Cold reset') end
  return root
end

function M.select(path, return_what, length, cla)
  return util.select(path, return_what, length, cla)
end

function M.read_record(sfi, record, length, cla)
  return util.read_record(sfi, record, length, cla)
end

function M.read_binary(offset, length, cla)
  return util.read_binary(offset, length, cla)
end

function M.get_data(tag, length, cla)
  return util.get_data(tag, length, cla)
end

function M.verify(pin, p1, p2)
  local data = cp.bytes.from_string(pin)
  return util.transmit(cp.bytes.pack(8, 0, 0x20, p1 or 0, p2 or 0, #data, data))
end

return M
