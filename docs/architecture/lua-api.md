# Lua API contract

The runtime provides native `cardpeek.bytes`, `cardpeek.card`, `cardpeek.nodes`,
`cardpeek.log`, `cardpeek.ui`, `cardpeek.asn1`, `cardpeek.crypto`, and
`cardpeek.encoding` modules.
It does not install legacy Cardpeek globals.
Ported analysers use these modules directly and keep shared code in native Lua modules.

For authoring instructions and examples, see [Write analyser scripts](../analysers.md).

## Runtime and startup

The runtime loads each analyser with `require("cardpeek")`.
The module exposes the Cardpeek-ng API through one namespace.
It does not install Cardpeek globals or emulate Cardpeek Lua behaviour.

Analyser discovery does not execute the analyser.
Metadata headers contain `@id`, `@title`, `@description`, and `@version` in leading Lua line comments.
Optional `@capabilities` values are `live`, `decode`, and `replay`.
A decoder also declares `@capture-schema`.
Discovery records these capabilities without executing Lua.
Scripts without the new headers default to live collection and replay.
Analyser entry points are directly inside the library's `cards/` directory.
The library root is the Lua module and data-file root.
Shared modules, card-family modules, and data files stay below `shared/`.
Module loading and file access follow the trusted-script policy.
The first release does not provide `dofile` compatibility behaviour.
Each run receives fresh Lua state, fresh document identifiers, and stable sequential node identifiers.
The `cardpeek.card.atr()` and `cardpeek.card.reset()` calls return an ATR result and an error value.
The ATR result contains typed `bytes` and an optional source `record` identifier.
`cardpeek.card.transmit()` returns response data, status components, and a description.
Native failures use the separate error result.

## Collection and decoding

A live-only analyser uses the legacy top-level execution path.
A migrated analyser defines `collect(cardpeek)` and `decode(cardpeek, captured)`.
Collection can use `cardpeek.card` and returns captured values with native bytes and source record identifiers.
The runtime stores those values in a capture bundle before decoding.
Standalone decoding receives the selected bundle and exposes bytes, nodes, logs, and captured data.
It does not install `cardpeek.card`.
Live collection and offline decoding therefore share the same decoder without sharing card access.

## API areas

| Module | Required behaviour | Initial validation |
| --- | --- | --- |
| `cardpeek.bytes` | Constructors, explicit widths, indexing, iteration, slices, concatenation, comparison, conversion, and formatting | Focused unit tests and ATR fixtures |
| `cardpeek.card` | Session information, reset, ATR access, explicit APDU transmission, protocol, and capabilities | Replay integration tests |
| `cardpeek.nodes` | Root access, append, navigation, attributes, typed values, and provenance | Document conformance tests |
| `cardpeek.log` | Structured levels and messages | Bounded event tests |
| `cardpeek.ui` | Questions, text input, secret input, and file selection | Broker integration tests |
| `cardpeek.progress` | Determinate and indeterminate progress | Application event tests |

The card API returns structured success and error values.
It does not perform implicit retries after status 6C.
It does not issue implicit GET RESPONSE commands after status 61.
Analysers may implement those operations explicitly.

Binary values cross the Lua boundary as typed native values.
Legacy `1:`, `4:`, and `8:` prefixes remain confined to XML conversion.

Each bundled analyser has replay fixtures and expected result documents.
