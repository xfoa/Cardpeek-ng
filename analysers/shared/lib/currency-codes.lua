local M = {}

local currencies = {
  [36] = { 'Australian dollar', 2 }, [124] = { 'Canadian dollar', 2 },
  [156] = { 'Yuan renminbi', 2 }, [203] = { 'Czech koruna', 2 },
  [208] = { 'Danish krone', 2 }, [344] = { 'Hong Kong dollar', 2 },
  [348] = { 'Hungarian forint', 2 }, [352] = { 'Icelandic krona', 0 },
  [356] = { 'Indian rupee', 2 }, [360] = { 'Indonesian rupiah', 2 },
  [376] = { 'Israeli new shekel', 2 }, [392] = { 'Japanese yen', 0 },
  [410] = { 'South Korean won', 0 }, [458] = { 'Malaysian ringgit', 2 },
  [484] = { 'Mexican peso', 2 }, [554] = { 'New Zealand dollar', 2 },
  [578] = { 'Norwegian krone', 2 }, [586] = { 'Pakistani rupee', 2 },
  [608] = { 'Philippine peso', 2 }, [616] = { 'Polish zloty', 2 },
  [643] = { 'Russian ruble', 2 }, [682] = { 'Saudi riyal', 2 },
  [702] = { 'Singapore dollar', 2 }, [710] = { 'South African rand', 2 },
  [752] = { 'Swedish krona', 2 }, [756] = { 'Swiss franc', 2 },
  [764] = { 'Thai baht', 2 }, [792] = { 'Turkish lira', 2 },
  [784] = { 'UAE dirham', 2 }, [826] = { 'Pound sterling', 2 },
  [840] = { 'US dollar', 2 }, [978] = { 'Euro', 2 },
}

function M.name(code)
  local item = currencies[code]
  return item and item[1] or string.format('Unknown currency code %s', tostring(code))
end

function M.digits(code)
  local item = currencies[code]
  return item and item[2] or 2
end

return M
