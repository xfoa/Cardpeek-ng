-- Cardpeek-ng ATR analyser.
-- @id atr
-- @title Card read
-- @description Read the current Answer to Reset
-- @version 1.0.0
-- @capabilities live, decode, replay
-- @capture-schema atr/v1

function collect(cardpeek)
    local atr, failure = cardpeek.card.atr()
    assert(failure == nil, failure and failure.message or "ATR failed")
    return {{ name = "atr", bytes = atr.bytes, source = atr.record }}
end

function decode(cardpeek, captured)
    local root = cardpeek.nodes.root()
    local card = root:append("card", "Card")
    local atr_node = card:append("atr", "Answer to Reset")
    local atr = captured[1]
    atr_node:set("value", atr.bytes)
    atr_node:set_provenance(atr.source, "Cold reset")
    cardpeek.log.info("Read " .. tostring(#atr.bytes) .. " ATR bytes")
end

local cardpeek = require("cardpeek")
if cardpeek.capture_execution == nil and cardpeek.captured == nil and cardpeek.card ~= nil then
    decode(cardpeek, collect(cardpeek))
end
