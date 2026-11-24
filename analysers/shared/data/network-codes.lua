local M = {}

local networks = {
  [250] = { [1] = 'Paris', [64] = 'Grenoble', [502] = 'Brussels', [901] = 'Gironde' },
  [56] = { [1] = 'Brussels' },
  [131] = { [1] = 'Lisbon' },
  [376] = { [2] = 'RavKav' },
}

function M.name(country, network)
  local item = networks[country] and networks[country][network]
  return item or string.format('Unknown network %s/%s', tostring(country), tostring(network))
end

return M
