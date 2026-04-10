# Forensic Copy

Forensically sound file copy tool with cryptographic hash verification.  Copies
one or more source directories or files to a destination, computing and
verifying hashes (SHA-256, BLAKE3, or MD5) to confirm bit-for-bit integrity.
Preserves timestamps, permissions, ownership, and extended attributes.

## Usage

```
forensic_copy --source <path> [--source <path> ...] --destination <path> [options]
forensic_copy <source> <destination>   # legacy positional form
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--source <path>` | Source file or directory (repeatable) | required |
| `--destination <path>` | Destination directory (created if missing) | required |
| `--hash sha256\|blake3\|md5` | Hash algorithm | `sha256` |
| `--no-hash` | Skip hashing entirely | off |
| `--no-verify` | Hash source only, skip destination re-hash | off |
| `--on-conflict skip\|overwrite\|abort` | Conflict resolution | `skip` |
| `--report` | Print forensic report to stdout | off |
| `--report-path <path>` | Write forensic report to file (implies `--report`) | — |
| `--icloud` | Enable iCloud Production mode (forces SHA-256 + full verify) | off |
| `--icloud-csv <path>` | Explicit Apple production CSV path | auto-detect |

`--no-hash` and `--no-verify` are mutually exclusive.

## Build

```sh
cargo build --release
```

The binary is placed at `target/release/forensic_copy`.

## Documentation

The man page is located at `docs/Forensic_Copy.1`.  To install it system-wide
after building:

```sh
make install-man
```

This copies `docs/Forensic_Copy.1` to the appropriate `man1` directory
(`/usr/local/share/man/man1` preferred, `/usr/share/man/man1` as fallback) and
runs `mandb` or `makewhatis` to update the man database.  Root or sudo
privileges are typically required.

Once installed:

```sh
man Forensic_Copy
```

To preview the man page without installing:

```sh
man docs/Forensic_Copy.1
# or
groff -man -Tascii docs/Forensic_Copy.1 | less
```
