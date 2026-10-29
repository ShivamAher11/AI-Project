# Verified dependency and tool versions

Verify each item against official documentation or release artifacts at implementation start, then record the exact version, relevant flags/compatibility, verification date, and official source URL. Status remains TODO until recorded.

| Item | Target / requirement from SPEC | Status | Exact pin / verification evidence |
|---|---|---|---|
| Ghidra | 12.1.3 target; verify release asset, JDK 21 compatibility, and headless flags/APIs | TODO | |
| JDK | Java 21; exact patch compatible with pinned Ghidra | TODO | |
| LIEF | 1.0.x | VERIFIED 2026-10-29 | `lief==1.0.0`. Official 1.0.0 release: https://github.com/lief-project/LIEF/releases/tag/1.0.0 ; PyPI 1.0.0 files: https://pypi.org/project/lief/1.0.0/ . Verified PE Python API: https://lief.re/doc/latest/formats/pe/python.html — `lief.PE.ParserConfig.default_conf` with `parse_imports`/`parse_exports`, `lief.PE.parse(path, config)` returns `lief.PE.Binary | None`; `binary.header.machine` (`0x8664` AMD64), `binary.optional_header.magic` (`0x20b` PE32+), `imagebase + addressof_entrypoint`; sections expose `virtual_address`, `virtual_size`, `sizeof_raw_data`, `characteristics`, `content`; imports iterate `binary.imports → Import.entries` and use `ImportEntry.is_ordinal`, `.ordinal`, `.name`, `.iat_address`; exports use `binary.get_export().entries` with `.name`, `.address`, `.ordinal`. |
| Capstone | Stable exact pin; verify official release | TODO | |
| PostgreSQL | `postgres:16.15-alpine` | VERIFIED 2026-10-29 | Official PostgreSQL versioning lists 16.15 as the current supported 16.x minor and recommends current minor releases: https://www.postgresql.org/support/versioning/ |
| Celery | `5.6.3`; worker uses prefork, concurrency 1 | VERIFIED 2026-10-29 | Official stable documentation identifies the 5.6 series: https://docs.celeryq.dev/en/stable/ |
| networkx | Verify exact version for deterministic graph/PageRank behavior | TODO | |
