local cp = require('cardpeek')
local util = require('shared.lib.util')

return function(root)
  local atr, failure = cp.card.atr()
  if failure then error(failure.message) end
  local encoded = cp.bytes.sub(atr.bytes, -7, -4)
  if not encoded then return end
  local number = cp.bytes.number(encoded)
  util.node(root, 'item', 'Calypso card number', encoded, string.format('%.0f', number))
end
