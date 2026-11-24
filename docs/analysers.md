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

## Compatibility

Cardpeek-ng does not support analysers written for the original Cardpeek API.
Do not use the legacy `card`, `bytes`, `nodes`, or `ui` globals.
The bundled original Cardpeek analysers have been reimplemented with the native API.
No legacy compatibility layer is installed.

## Bundled analysers

The bundled analysers are ATR, GSM/USIM, Belgian eID, Finnish eID, Finnish eTravel,
Calypso, ePassport, EMV, legacy GSM, MIFARE Classic, Moneo, OpenPGP, Tachograph,
Thai eID, and Vitale 2.
Shared Lua modules and data files are bundled in new personal analyser libraries.

### Finnish eID

The Finnish eID analyser supports the FINEID S1 and S4-1 citizen-card profiles.
It reads public CIA metadata, object directories, and X.509 certificates through the contact interface.
It follows the file paths in the object directory and supports optional certificate directories.
The analyser does not request PINs or perform private-key operations.
The FINEID application contains certificate data, not the visual identity record printed on the card.
The analyser does not validate certificate signatures or revocation status.
See the [DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) for the card profile.

### Finnish eTravel

The separate Finnish eTravel analyser reads the ICAO eMRTD application on a Finnish Henkilokortti.
It supports PACE-ECDH generic mapping with Brainpool P-384r1 and AES-256-CBC-CMAC.
It accepts a card access number (CAN) or the MRZ access data.
It does not request a PIN or PUK.
The analyser validates the PACE profile in EF.CardAccess before requesting the secret.
It reads DG1, DG2, DG14, and EF.SOD through PACE secure messaging.
It extracts the DG2 facial photograph as JPEG or JPEG 2000.
It displays data and does not verify the EF.SOD signature, certificate chain, or passive authentication.
It does not write card data.
The general ePassport analyser remains separate and uses Basic Access Control.

## Create a first analyser

Create a library directory at `temp/analysers/`.
Create its `cards/` directory.
Add a file named `temp/analysers/cards/atr-example.lua` with this content:

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
cargo run -p cardpeek-cli -- discover temp/analysers
```

Replay a synthetic trace without a card or reader:

```sh
cargo run -p cardpeek-cli -- replay \
  tests/fixtures/traces/atr-synthetic-001.json \
  atr-example \
  --analysers temp/analysers \
  --output temp/atr-example-result.json
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
It can use bytes, nodes, logs, structured-data modules, and cryptography.
It cannot use `cardpeek.card`.
The runtime sets `cardpeek.captured` to the same array during capture execution and offline decoding.
The runtime sets `cardpeek.capture_execution` to `true` during capture execution and offline decoding.

Every captured value must reference an existing trace record in the selected segment.
The current card API exposes a source record identifier only for ATR results.
Capture collection cannot record an APDU source through the current API.

The bundled [ATR analyser](../analysers/cards/atr.lua) shows the complete pattern.
The runtime always executes the script at top level before it calls `collect` or `decode`.
Top-level code must not access the card before the runtime calls `collect`.
Use this condition for a CLI fallback:

```lua
local cardpeek = require("cardpeek")
if cardpeek.capture_execution == nil and cardpeek.captured == nil and cardpeek.card ~= nil then
  decode(cardpeek, collect(cardpeek))
end
```

The CLI `run` and `replay` commands execute only the script at top level.
They do not call `collect` or `decode`.
Keep this fallback when a capture-capable analyser must support these commands.
A capture-capable script without this fallback produces an empty document during replay.
The desktop replay command also executes only the script at top level.
The desktop uses a compatible capture bundle for offline decoding when one exists.
Otherwise, it uses replay.

## Work with byte strings

A byte string contains 1-bit, 4-bit, or 8-bit elements.
Use 8-bit elements for APDU commands and responses.
The width remains attached to the value in the result document.

### Constructors and operations

| Call | Result |
| --- | --- |
| `cardpeek.bytes.new(width, values)` | Create a byte string from an array of integers. The width must be 1, 4, or 8. |
| `cardpeek.bytes.from_hex(text)` | Create an 8-bit byte string from hexadecimal text. |
| `cardpeek.bytes.from_hex(text, width)` | Create a byte string with the selected width. |
| `cardpeek.bytes.from_string(text)` | Create an 8-bit byte string from the text bytes. |
| `cardpeek.bytes.pack(width, ...)` | Combine integers, hexadecimal strings, and byte strings of the selected width. |
| `cardpeek.bytes.concat(...)` | Concatenate values. Non-byte-string values become 8-bit values. The first byte string sets the width. |
| `cardpeek.bytes.get(data, index)` | Return an element with a zero-based index, or `nil`. A `nil` input returns `nil`. |
| `cardpeek.bytes.sub(data, first, last)` | Return an inclusive zero-based range. Negative indices count from the end. The first index and the last index are optional. |
| `cardpeek.bytes.number(data)` | Convert a value to an unsigned integer. Values outside Lua's signed integer range are rejected. A `nil` input returns zero. |
| `cardpeek.bytes.format(data, format)` | Format bytes with `%D`, `%S`, `%w`, `%l`, `%I`, `%C`, `%P`, or `%%`. |
| `cardpeek.bytes.printable(data)` | Report whether a nonempty value contains only printable ASCII. |
| `cardpeek.bytes.reverse(data)` | Reverse the element order. |
| `cardpeek.bytes.pad_left(data, length, value)` | Pad the left side to the selected element count. |
| `cardpeek.bytes.pad_right(data, length, value)` | Pad the right side to the selected element count. |

Hexadecimal input can contain spaces, colons, hyphens, and underscores.
An 8-bit value requires two hexadecimal digits for each byte.
A 4-bit value requires one hexadecimal digit for each element.
A 1-bit value accepts only `0` and `1`.
An empty `cardpeek.bytes.concat()` call returns an empty 8-bit value.
`cardpeek.bytes.sub` returns `nil` when the range is invalid or starts after the value.
The last index is inclusive.
It defaults to the end of the value.
`cardpeek.bytes.pad_left` and `cardpeek.bytes.pad_right` do not truncate an existing value.
The pad value must fit the element width.

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
| `data:to_string()` | Decode an 8-bit value as UTF-8 text. Invalid UTF-8 raises a Lua error. Another width returns empty text. |
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
`split(data)` returns the tag, value, and remaining bytes.
`split_tag(data)` returns the tag and remaining bytes.
`split_length(data)` returns the decoded length and remaining bytes.
The remaining bytes are `nil` when no bytes remain.
Malformed or incomplete input returns `nil` values.
`join(tag, value, tail)` encodes a tag and an 8-bit value.
The optional tail follows the encoded element.
Indefinite lengths are not supported.

The native `cardpeek.tlv` module builds labelled result trees.
Use `parse(parent, data, reference)` for a sequence and `one(parent, tag, value, reference)` for one known element.
The optional reference maps tag names to `{ label, decoder }` entries.
Use `parentTag .. "/" .. tag` as the key for a nested tag.
A decoder receives a result node and a byte string.
It can return `false` to remove the new node.
It can return another value to keep the node.
The module supplies `number`, `printable`, `date`, `country`, `currency`, and `oid` decoders in `cardpeek.tlv.parsers`.
`info(tag, reference, parent)` returns a label and decoder.
`tag_type(tag)` returns the ASN.1 class label.
Empty constructed values produce an empty result node.
Malformed input produces an `Unparsed ASN1 data` node.
Nesting is limited to 64 levels.

### EN 1545

The native `cardpeek.en1545` module decodes scalar fields and maps format tables onto result records.
Scalar functions are `date`, `time`, `quarters`, `date_time`, `bcd_date`, `alpha`, `network_id`, `number`, `amount`, `zones`, and `undefined`.
The `is_all(data, value)` function reports whether a nonempty value contains only the selected element.
Dates and times use deterministic UTC calendar arithmetic.
`date` and `date_time` accept an optional reference timestamp.
A negative reference selects subtraction.

Use `map(root, condition, ...)` with one or more format tables.
A string condition selects a file by label and records by the label `record`.
A table condition supplies separate `file` and `record` criteria.
Each field is `{ decoder, bitLength, label, arguments }`.
The constants `BITMAP`, `REPEAT`, and `BITMAP_BE` select structural fields.
`BITMAP` selects fields from the least significant bit first.
`BITMAP_BE` selects fields from the most significant bit first.
`REPEAT` uses its first child as the repeated field.
Custom scalar decoders receive a byte string and optional arguments.
They return display text or `nil` to omit the field.
The map function stores remaining nonzero bits in an `(remaining unparsed data)` node.

Country, currency, and network lookup modules are in `shared.data`.
Use `shared.data.country-codes`, `shared.data.currency-codes`, and `shared.data.network-codes`.

### Cryptography

The `cardpeek.crypto` module provides SHA-1, SHA-256, AES-256-CBC, AES-CMAC,
two-key Triple DES CBC, and ISO 9797 MAC.
Use `sha1(data)`, `sha256(data)`, `aes_cbc(encrypt, key, iv, data)`,
`aes_cmac(key, data)`, `des_ede3_cbc(encrypt, key, iv, data)`,
and `iso9797_mac(key, data)`.
Keys and data must use 8-bit elements.
AES uses a 32-byte key and a 16-byte initialisation vector.
AES-CMAC uses a 32-byte key.
Triple DES uses a 16-byte key and an 8-byte initialisation vector.
AES and Triple DES data must contain complete blocks.
Apply the required padding in the analyser.
`iso9797_mac` applies ISO/IEC 9797-1 padding method 2 and MAC algorithm 3.
It returns an 8-byte MAC.

PACE support uses `pace_new(credential, secret)` to create a session.
The credential name is `mrz`, `can`, `pin`, or `puk`.
The bundled Finnish eTravel analyser uses only CAN and MRZ.
The optional `pace_new(credential, secret, mapping_scalar, ephemeral_scalar)` form accepts fixed scalars for deterministic tests.
Each fixed scalar must contain 48 bytes.
Do not use fixed scalars for live analysis.

Call `pace_handshake(session)` to obtain MSE:Set AT.
For each returned command, transmit it to the card.
Then call `pace_handshake(session, response)` with the response data and status.
Repeat until the function returns `nil`.
The session validates response statuses, public keys, and the card authentication token.

Use `pace_protect(session, command)` before transmitting a protected command.
Use `pace_unprotect(session, response)` on the protected response bytes and final status.
Construct this input as `cardpeek.bytes.concat(response.data, cardpeek.bytes.from_hex("9000"))` after a successful transmission.
The second function returns a table with `data` and `status` fields.
The `status` field contains the status from DO99.
The function rejects invalid checksums, padding, and unexpected response objects.
The PACE profile supports short APDUs only.

### Character encodings

Use `cardpeek.encoding.decode(name, data)` for UTF-8, TIS-620, and ISO-8859-1 through ISO-8859-16 except ISO-8859-12.
Encoding names are not case-sensitive.
The decoder maps ISO-8859-1 to Windows-1252, ISO-8859-9 to Windows-1254, and TIS-620 to Windows-874.
Invalid input or an unsupported encoding raises a Lua error.

### Byte iteration and tests

`data:ipairs()` returns zero-based index and value pairs.
`cardpeek.bytes.all(data, value)` reports whether a nonempty value contains only the selected element.
Use these functions for bitfield and transport decoders.

### Node queries and removal

`cardpeek.nodes.find(parent, criteria)` returns an iterator over recursive matches.
`cardpeek.nodes.find_first(parent, criteria)` returns the first match or `nil`.
A search includes the parent node when it matches.
Criteria use `class`, `label`, `identifier`, `alternative`, and `mime_type`.
The aliases `classname`, `id`, `alt`, and `mime-type` are accepted.
Numeric criteria are converted to strings.
`node:find(criteria)` and `node:find_first(criteria)` provide the same search operations.
`node:remove()` removes a node and its children from the document.
It returns `true` when the runtime removes the node.

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
Its `id()` method returns `nil`.
Its `parent()` method returns `nil`.
Its `children()` method returns the top-level nodes.

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
| `node:find(criteria)` | Return an iterator over recursive matches. |
| `node:find_first(criteria)` | Return the first recursive match or `nil`. |
| `node:remove()` | Remove the node and its children. Return whether the runtime removed the node. |

The supported attribute fields are:

| Field | Value |
| --- | --- |
| `class` | A string that identifies the node type. |
| `label` | A display string. |
| `identifier` | An optional analyser-defined string. Text, numbers, and `nil` are accepted. |
| `alternative` | Optional decoded display text. Text, numbers, and `nil` are accepted. |
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
local codec = require("shared.lib.util")
```

The runtime starts each analyser with a new Lua state.
Do not use global variables to retain data between runs.
The runtime replaces the Lua module search path with paths below the analyser library root.
Do not use `dofile` for dependencies.
Use `require` with a path relative to the library root.

## Test an analyser

Start with static discovery.
This step checks the metadata without executing Lua.

```sh
cargo run -p cardpeek-cli -- discover temp/analysers
```

Then use replay with a synthetic trace.
Replay does not need a card or reader.

```sh
cargo run -p cardpeek-cli -- replay \
  tests/fixtures/traces/atr-synthetic-001.json \
  atr-example \
  --analysers temp/analysers \
  --output temp/atr-example-result.json
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
