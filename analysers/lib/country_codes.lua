local M = {}

local names = {
  [4] = 'Afghanistan', [8] = 'Albania', [12] = 'Algeria', [20] = 'Andorra',
  [24] = 'Angola', [32] = 'Argentina', [36] = 'Australia', [40] = 'Austria',
  [50] = 'Bangladesh', [56] = 'Belgium', [64] = 'Bhutan', [68] = 'Bolivia',
  [70] = 'Bosnia and Herzegovina', [76] = 'Brazil', [100] = 'Bulgaria',
  [124] = 'Canada', [152] = 'Chile', [156] = 'China', [170] = 'Colombia',
  [188] = 'Costa Rica', [191] = 'Croatia', [192] = 'Cuba', [196] = 'Cyprus',
  [203] = 'Czechia', [208] = 'Denmark', [214] = 'Dominican Republic',
  [218] = 'Ecuador', [818] = 'Egypt', [222] = 'El Salvador', [233] = 'Estonia',
  [246] = 'Finland', [250] = 'France', [268] = 'Georgia', [276] = 'Germany',
  [288] = 'Ghana', [300] = 'Greece', [320] = 'Guatemala', [340] = 'Honduras',
  [348] = 'Hungary', [352] = 'Iceland', [356] = 'India', [360] = 'Indonesia',
  [364] = 'Iran', [368] = 'Iraq', [372] = 'Ireland', [376] = 'Israel',
  [380] = 'Italy', [388] = 'Jamaica', [392] = 'Japan', [400] = 'Jordan',
  [398] = 'Kazakhstan', [404] = 'Kenya', [410] = 'South Korea', [414] = 'Kuwait',
  [428] = 'Latvia', [422] = 'Lebanon', [434] = 'Libya', [438] = 'Liechtenstein',
  [440] = 'Lithuania', [442] = 'Luxembourg', [458] = 'Malaysia', [470] = 'Malta',
  [484] = 'Mexico', [492] = 'Monaco', [496] = 'Mongolia', [499] = 'Montenegro',
  [504] = 'Morocco', [528] = 'Netherlands', [554] = 'New Zealand',
  [558] = 'Nicaragua', [566] = 'Nigeria', [578] = 'Norway', [512] = 'Oman',
  [586] = 'Pakistan', [591] = 'Panama', [600] = 'Paraguay', [604] = 'Peru',
  [608] = 'Philippines', [616] = 'Poland', [620] = 'Portugal', [630] = 'Puerto Rico',
  [634] = 'Qatar', [642] = 'Romania', [643] = 'Russia', [682] = 'Saudi Arabia',
  [688] = 'Serbia', [702] = 'Singapore', [703] = 'Slovakia', [705] = 'Slovenia',
  [710] = 'South Africa', [724] = 'Spain', [144] = 'Sri Lanka', [752] = 'Sweden',
  [756] = 'Switzerland', [760] = 'Syria', [158] = 'Taiwan', [764] = 'Thailand',
  [780] = 'Trinidad and Tobago', [788] = 'Tunisia', [792] = 'Turkey',
  [804] = 'Ukraine', [784] = 'United Arab Emirates', [826] = 'United Kingdom',
  [840] = 'United States', [858] = 'Uruguay', [862] = 'Venezuela',
  [704] = 'Vietnam', [716] = 'Zimbabwe', [131] = 'Calypso network 131',
}

function M.name(code)
  return names[code] or string.format('Unknown country code %s', tostring(code))
end

return M
