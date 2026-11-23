# Write analyser scripts

An analyser is a Lua script that reads card data and builds a result document.
Cardpeek-ng uses Lua 5.4.
The script uses the `cardpeek` module for bytes, card access, result nodes, and logs.

This guide describes the implemented application programming interface (API).
For the design contract, see [Lua API contract](architecture/lua-api.md).

## Safety

Analyser scripts are trusted code.
Cardpeek-ng does not sandbox them.
Run only scripts that you trust.

Card commands can change card state or block authentication methods.
Use a disposable test card during development.
Do not test with a card that contains live credentials or personal data.
Do not write secret values to logs, result documents, or fixtures.

Cardpeek-ng does not support analysers written for the original Cardpeek API.
Do not use the legacy `card`, `bytes`, `nodes`, or `ui` globals.
The bundled original Cardpeek analysers have been reimplemented with the native API.
No legacy compatibility layer is installed.

The bundled analysers are ATR, GSM/USIM, Belgian eID, Calypso, ePassport, EMV,
legacy GSM, MIFARE Classic, Moneo, OpenPGP, Tachograph, Thai eID, and Vitale 2.
Shared Lua modules and data files are bundled in new personal analyser libraries.

## Create a first analyser

Create a `cards/` directory for local development.
Add a file named `cards/atr.lua` with this content:

```lua
-- Read the Answer to Reset (ATR).
-- @id atr-example
-- @title ATR example
-- @description Read and display the Answer to Reset
-- @version 1.0.0
-- @capabilities live, replay

local cardpeek = require("cardpeek")

local atr, failure = cardpeek.card.atr()
assert(failure == nil, failure and failure.message or "ATR read failed")

local root = cardpeek.nodes.root()
local card = root:append("card", "Card")
local node = card:append("atr", "Answer to Reset")
node:set("value", atr.bytes)
node:set("identifier", "atr")
if atr.record ~= nil then
  node:set_provenance(atr.record, "Card reset")
end

cardpeek.log.info("Read " .. tostring(#atr.bytes) .. " ATR bytes")
```

The `require("cardpeek")` call returns the API namespace.
The runtime does not install global Cardpeek names.
Each run starts with a new Lua state and a new result document.

Check the metadata without running the script:

```sh
cargo run -p cardpeek-cli -- discover /path/to/analysers
```

Replay a synthetic trace without a card or reader:

```sh
cargo run -p cardpeek-cli -- replay \
  tests/fixtures/traces/atr-synthetic-001.json \
  atr-example \
  --analysers /path/to/analysers \
  --output /tmp/atr-example-result.json
```

The replay host supplies the recorded ATR.
The command writes the result document to the requested path.

## Add metadata

Discovery reads the leading Lua comments.
It does not execute the script.
Put every metadata directive before the first executable line.

```lua
-- @id example-card
-- @title Example card
-- @description Read public data from an example card
-- @version 1.0.0
-- @capabilities live, decode, replay
-- @capture-schema example-card/v1
```

| Directive | Required | Purpose |
| --- | --- | --- |
| `@id` | Yes | Give a stable and unique identifier for commands and library management. |
| `@title` | Yes | Give the name that the application displays. |
| `@description` | Yes | Describe the analyser in one short statement. |
| `@version` | Yes | Identify the analyser release. |
| `@capabilities` | No | List supported execution modes. The default is `live, replay`. |
| `@capture-schema` | For `decode` | Identify the layout of captured values. |

Separate capability names with commas.
The available names are `live`, `decode`, and `replay`.
The `decode` capability requires `@capture-schema`.

Change `@capture-schema` when the capture layout becomes incompatible.
Change `@version` for each analyser release.
Offline decoding requires an exact match for the analyser identifier, version, and capture schema.

Discovery examines only Lua files directly inside the selected library's `cards/` directory.
The library rejects duplicate identifiers and duplicate destination names.

## Select an execution model

Cardpeek-ng supports three analyser operations:

- **Live** accesses a connected card.
- **Replay** accesses exchanges from a recorded trace segment.
- **Decode** processes captured values without card access.

A top-level script supports live execution and replay through `cardpeek.card`.
The first example uses this model.
The replay host matches each transmitted command with a recorded exchange.

A capture-capable analyser separates collection from decoding.
Use this model when the desktop application must retain values for offline decoding.
Define these global functions:

```lua
function collect(cardpeek)
  -- Return an array of captured values.
end

function decode(cardpeek, captured)
  -- Build the result document without card access.
end
```

The `collect` function can use `cardpeek.card`.
It returns an array of tables.
Each table contains these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `name` | String | Give a unique name inside the capture bundle. |
| `bytes` | Byte string | Store one captured binary value. |
| `source` | String | Identify the source trace record. |

The `decode` function receives the captured array in the same order.
It can use bytes, nodes, and logs.
It cannot use `cardpeek.card`.
The runtime sets `cardpeek.captured` to the same array during capture execution and offline decoding.

The current card API exposes a source record identifier for ATR results.
It does not expose a source record identifier in APDU responses.
Every captured value must reference an existing trace record in the selected segment.

The bundled [ATR analyser](../analysers/cards/atr.lua) shows the complete pattern.
Its top-level condition also supports live execution through the CLI.
Keep this fallback when a capture-capable analyser must support the CLI `run` command.
The CLI `run` and `replay` commands execute the script at top level.

## Work with byte strings

A byte string contains 1-bit, 4-bit, or 8-bit elements.
Use 8-bit elements for APDU commands and responses.
The width remains attached to the value in the result document.

### Constructors

| Call | Result |
| --- | --- |
| `cardpeek.bytes.new(width, values)` | Create a byte string from an array of integers. The width must be 1, 4, or 8. |
| `cardpeek.bytes.from_hex(text)` | Create an 8-bit byte string from hexadecimal text. |
| `cardpeek.bytes.from_hex(text, width)` | Create a byte string with the selected width. |
| `cardpeek.bytes.from_string(text)` | Create an 8-bit byte string from the text bytes. |

Hexadecimal input can contain spaces, colons, hyphens, and underscores.
An 8-bit value requires two hexadecimal digits for each byte.

```lua
local command = cardpeek.bytes.from_hex("00 A4 04 00 02 3F 00")
local text = cardpeek.bytes.from_string("ABC")
local nibbles = cardpeek.bytes.new(4, { 3, 11, 0 })
```

### Methods and operators

| Expression | Result |
| --- | --- |
| `data:width()` | Return the width of each element in bits. |
| `data:len()` | Return the number of elements. |
| `data:bit_len()` | Return the size in bits. |
| `data:to_hex()` | Return uppercase hexadecimal text. |
| `data:to_string()` | Decode an 8-bit value as UTF-8 text. |
| `data:elements()` | Return the elements as a Lua array. |
| `data:convert(width)` | Convert the value to width 1, 4, or 8. |
| `data:slice(start, length)` | Copy a range with a one-based start index. The length is optional. |
| `data:iter()` | Return an iterator over the element values. |
| `#data` | Return the number of elements. |
| `data[index]` | Return an element with a one-based index. |
| `left == right` | Compare the width and all elements. |
| `left .. right` | Concatenate two values with the same width. |
| `tostring(data)` | Return uppercase hexadecimal text. |

A slice stops at the end of the value.
An index outside the value returns `nil`.
Conversion to a wider width left-aligns an incomplete final element.

```lua
local first = command[1]
local data = command:slice(6, 2)
assert(command:to_hex() == "00A40400023F00")
for value in data:iter() do
  cardpeek.log.debug(string.format("%02X", value))
end
```

## Access a card

The card module is available during live execution and replay.
Offline decoding does not install this module.

### Session information

| Expression | Result |
| --- | --- |
| `cardpeek.card.protocol` | Return `t0`, `t1`, or `other`. |
| `cardpeek.card.capabilities.extended_apdus` | Report extended APDU support. |
| `cardpeek.card.info()` | Return a table that contains the protocol. |

### Reset and ATR

These calls return two values:

```lua
local atr, failure = cardpeek.card.atr()
local atr, failure = cardpeek.card.reset("cold")
local atr, failure = cardpeek.card.reset("warm")
```

On success, `failure` is `nil`.
The result contains `bytes` and an optional `record` string.
On failure, the result is `nil`.
The failure contains `message` and `cancelled` fields.

Check the failure before you use the result:

```lua
local atr, failure = cardpeek.card.atr()
if failure ~= nil then
  error(failure.message)
end
```

## Use structured data and conversion modules

### BER-TLV

The `cardpeek.asn1` module provides `split`, `split_tag`, `split_length`, and `join`.
`split` returns tag, value, and remaining bytes.
Malformed or incomplete input returns `nil` values.
`join` encodes a tag and an 8-bit value.

The shared `shared.lib.tlv` module builds labelled result trees from these values.
It is a native Lua module, not a legacy global.

### Cryptography

The `cardpeek.crypto` module provides SHA-1, two-key Triple DES CBC, and ISO 9797 MAC.
Use `sha1(data)`, `des_ede3_cbc(encrypt, key, iv, data)`, and `iso9797_mac(key, data)`.
Keys and data must use 8-bit elements.
Triple DES data must contain complete blocks.
Apply the required padding in the analyser.

### Character encodings

Use `cardpeek.encoding.decode(name, data)` for UTF-8, ISO-8859 variants, and TIS-620.
Invalid input or an unsupported encoding raises a Lua error.

### Byte iteration and tests

`data:ipairs()` returns zero-based index and value pairs.
`cardpeek.bytes.all(data, value)` reports whether a nonempty value contains only the selected element.
Use these functions for bitfield and transport decoders.

### Node queries and removal

`cardpeek.nodes.find(parent, criteria)` returns an iterator over recursive matches.
`cardpeek.nodes.find_first(parent, criteria)` returns the first match or `nil`.
Criteria use `class`, `label`, `identifier`, `alternative`, and `mime_type`.
The aliases `classname`, `id`, `alt`, and `mime-type` are accepted.
`node:remove()` removes a node from its parent.

### Transmit an APDU

An Application Protocol Data Unit (APDU) contains a card command or response.
Create the full command as an 8-bit byte string.
Then transmit it:

```lua
local response, failure = cardpeek.card.transmit(command)
assert(failure == nil, failure and failure.message or "APDU failed")

if response.status == 0x9000 then
  cardpeek.log.info("Received " .. tostring(#response.data) .. " bytes")
else
  cardpeek.log.warning(response.description)
end
```

The response contains these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `data` | Byte string | Contain the response data without the status word. |
| `status` | Integer | Contain the complete status word. |
| `sw1` | Integer | Contain the first status byte. |
| `sw2` | Integer | Contain the second status byte. |
| `description` | String | Describe the status word. |

A non-success status word is a valid card response.
It is not a native failure.
The runtime does not retry a command after status `6Cxx`.
It does not send GET RESPONSE after status `61xx`.
Implement these operations explicitly when the card specification requires them.
Limit retry loops and preserve the final status.

## Build a result document

A result document contains an ordered tree of nodes.
Use classes to identify node types.
Use labels for display text.
Keep the original binary value when a decoded text value is also available.

```lua
local root = cardpeek.nodes.root()
local card = root:append("card", "Example card")
local file = card:append("file", "Master File")
file:set("identifier", "3F00")
file:set("value", response.data)
file:set("alternative", "Selected")
file:set("mime_type", "application/octet-stream")
```

### Document functions

| Call | Result |
| --- | --- |
| `cardpeek.nodes.root()` | Return the document root. |
| `cardpeek.nodes.roots()` | Return the top-level nodes as an array. |
| `cardpeek.nodes.get(id)` | Return a node by its runtime identifier, or `nil`. |

The document root can contain child nodes.
It has no attributes.

### Node functions

| Call | Result |
| --- | --- |
| `node:append(class, label)` | Append a child and return its handle. |
| `node:parent()` | Return the parent, or `nil` for a top-level node. |
| `node:children()` | Return the ordered children as an array. |
| `node:id()` | Return the stable runtime identifier. |
| `node:get(field)` | Read an attribute. |
| `node:set(field, value)` | Write an attribute. |
| `node:set_provenance(record, operation)` | Link the node to a trace record. The operation is optional. |

The supported attribute fields are:

| Field | Value |
| --- | --- |
| `class` | A string that identifies the node type. |
| `label` | A display string. |
| `identifier` | An optional analyser-defined string. |
| `alternative` | Optional decoded display text. |
| `mime_type` | An optional MIME type for the primary value. |
| `value` | Text, a byte string, or `nil`. |
| `size_bits` | The derived size of the primary value. This field is read-only. |

Setting `value` calculates `size_bits`.
Setting `value` to `nil` clears the value and its size.
Do not confuse `node:id()` with the analyser-defined `identifier` attribute.

Use provenance to connect a decoded value with its source exchange:

```lua
file:set_provenance("record-0002", "SELECT Master File")
```

The record identifier must exist in the related trace.
In capture-based decoding, use the `source` value from the captured entry.

## Write logs

Use the log functions for diagnostic messages:

```lua
cardpeek.log.debug("Detailed diagnostic message")
cardpeek.log.info("Normal progress message")
cardpeek.log.warning("Recoverable problem")
cardpeek.log.error("Operation failure")
```

Do not log PINs, keys, authentication values, or private cardholder data.
Use warnings for recoverable card or decoding problems.
Return a native failure or raise a Lua error when the analyser cannot continue.

## Ask the user

Use a yes or no question for a decision, a notice for acknowledgement, and secret input for a PIN or password:

```lua
local confirmed = cardpeek.ui.question("Verify PIN1 once?")
cardpeek.ui.notice("PIN verified")
local pin = cardpeek.ui.secret("Enter PIN1")
```

Question calls return a boolean.
Notice calls wait for the user to select OK.
Secret calls return text.
Use `cardpeek.ui.text(prompt, default)` for visible text input.
Use `cardpeek.ui.file(prompt, must_exist)` for file selection.
These calls require an interactive frontend.
Replay and offline decoding do not prompt the user.
Never put a returned secret in a log or result document.

## Load local modules

The analyser library root is the module search root.
The runtime searches for `?.lua` and `?/init.lua` below that directory.
Keep dependencies in `shared/`.
Use `shared/lib/` for shared modules, `shared/data/` for reference data, and a card-family directory for analyser-specific modules.
Do not put dependencies in `cards/`.
Discovery examines only entry points directly inside `cards/`.

```lua
local codec = require("example_codec")
```

The runtime starts each analyser with a new Lua state.
Do not use global variables to retain data between runs.

## Test an analyser

Start with static discovery.
This step checks the metadata without executing Lua.

```sh
cargo run -p cardpeek-cli -- discover /path/to/analysers
```

Then use replay with a synthetic trace.
Replay does not need a card or reader.

```sh
cargo run -p cardpeek-cli -- replay \
  tests/fixtures/traces/atr-synthetic-001.json \
  atr-example \
  --analysers /path/to/analysers \
  --output /tmp/atr-example-result.json
```

For a new card format, add a synthetic trace and an expected result document.
Follow the [test fixture policy](../tests/fixtures/README.md).
Do not commit live card captures or secrets.
Record the analyser version and fixture provenance.

Run the offline test suite before you submit a bundled analyser:

```sh
cargo test --workspace
```

Use hardware tests only after replay tests pass.
Follow the [hardware test guide](hardware-tests.md).
Use a disposable test card and commands with known effects.

## Install and update an analyser

Use an explicit analyser directory during development.
This method does not change the personal library.

Install an analyser when it is ready for regular use:

```sh
cargo run -p cardpeek-cli -- analysers import /path/to/analyser-library
```

The import command examines Lua files directly inside the source directory's `cards/` subdirectory.
It copies only selected entry points.
Copy any required modules and data files separately.
The desktop Library workspace can also import Lua files.
The desktop application and CLI use the same personal library.

List installed analysers and show the library path:

```sh
cargo run -p cardpeek-cli -- analysers list
```

The library does not overwrite an installed analyser.
To update one, remove its identifier and import the new file:

```sh
cargo run -p cardpeek-cli -- analysers remove atr-example
cargo run -p cardpeek-cli -- analysers import /path/to/analyser-library
```

A new personal library receives the bundled analysers.
An existing library does not receive them again after removal.

## Review before distribution

1. Check that every metadata field is correct.
2. Check that the analyser identifier is stable.
3. Test live, replay, and decode modes that the metadata declares.
4. Check native failures and non-success card statuses.
5. Limit loops that read records or request more response data.
6. Preserve binary values and source provenance.
7. Remove secrets from logs and result documents.
8. Add safe synthetic replay fixtures.
9. Record the required license and attribution notices.
10. State which cards and specifications the analyser supports.
