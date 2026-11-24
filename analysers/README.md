# Bundled analyser layout

This directory is an analyser library root.
Cardpeek-ng copies its contents when it creates a personal library.

## Directories

- `cards/` contains analyser entry points.
  Discovery reads only Lua files directly inside this directory.
  Name each file after its `@id` value, followed by `.lua`.
  Use lowercase words separated by hyphens.
- `shared/lib/` contains reusable Lua modules.
  Require these modules with names such as `shared.lib.util`.
- `shared/data/` contains reference data and data-only Lua modules.
- `shared/` also contains card-family decoders and lookup modules.
  Keep these dependencies outside `cards/` so discovery does not treat them as entry points.

The Lua module search root is this directory, not `cards/`.
Use dots for module path components in `require` calls.
For the shared helper reference, see [Shared Lua helpers](../docs/architecture/lua-api.md#shared-lua-helpers).

## Calypso modules

The Calypso entry point maps InterCode country and network codes to explicit module names.
Country modules decode common card data.
Network modules add issuer-specific decoding.

Directory names identify countries.
File names identify card products, transport networks, or data roles.
Do not encode country and network numbers as compact `cNNNnMMM` file names.

## Imports

The import command copies entry points from another library's `cards/` directory.
It does not copy dependencies.
Copy required modules and data files separately when importing an analyser with dependencies.
