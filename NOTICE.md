# Notices and attribution

Cardpeek-ng is a new Rust implementation.
It is not the original [Cardpeek](https://github.com/l1l1/cardpeek) application, and is not related to nor endorsed by the original Cardpeek authors in any way.

## Cardpeek-ng

Copyright (C) 2026 Cardpeek-ng contributors.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.
If not, see <https://www.gnu.org/licenses/>.

The full license is in [`LICENSE`](LICENSE).

## Third-party Cardpeek material

The `analysers` directory contains native Cardpeek-ng reimplementations based on the
original Cardpeek Lua analysers and their shared data tables.
The original sources came from <https://github.com/l1l1/cardpeek>,
revision `de8cee209b870f3d7aa1c6bd55e84738765dc1e6`, retrieved on 2026-11-23.
They are distributed under GPL-3.0-or-later.
The original copyright notices are preserved in the relevant files.
The Cardpeek-ng changes include native API conversion, safety changes, and 2026-11-23 modifications.

The original analyser authors and contributors include Alain Pannetrat (`L1L1`),
Andreas Heiduk, David Huang, Darius Matboo, Adam Laurie, Tyson Key, and Andrew Kozlic.
The Calypso data tables retain their original public-information and experimental-status notices.
No endorsement by those authors is implied.

Before importing any third-party Cardpeek material:

1. Record the upstream project and exact source location.
2. Record the upstream revision or release and retrieval date.
3. Identify the copyright holders.
4. Verify the license and every additional permission or restriction.
5. Preserve copyright, license, warranty, and attribution notices.
6. Mark modifications and their dates when required.
7. Add third-party license texts required for distribution.
8. Update this notice file and the relevant package documentation.
9. Write new analysers against the Cardpeek-ng Lua API.
10. Reimplement legacy API calls instead of adding a compatibility layer.

Do not remove or replace upstream notices.
Do not imply endorsement by upstream authors.

## Vendored Blade Graphics dependency

The `vendor/blade-graphics` directory contains Blade Graphics 0.7.1 from <https://github.com/kvark/blade>.
Its MIT license is preserved in that directory.
The Vulkan adapter selection keeps Intel presentation when the NVIDIA kernel module is absent.
The PRIME file alone does not prove that an NVIDIA device is present.

## Vendored xattr dependency

The `vendor/xattr` directory contains xattr 0.2.3 from <https://github.com/Stebalien/xattr>.
Its MIT and Apache-2.0 license texts are preserved in that directory.
The Linux and BSD `ENOATTR` mapping uses `ENODATA` because those systems do not expose the macOS `ENOATTR` constant.

## Dependencies

Release packages must include the notices and license texts required by bundled dependencies.
Generate and review a third-party notice inventory when dependencies and packaging are introduced.
