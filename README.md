# .DS_Store Parser

A Python CLI tool that parses macOS `.DS_Store` files and outputs structured CSV or JSON for forensic analysis.

No external dependencies. Python 3.10+.

## What is a .DS_Store file?

`.DS_Store` (Desktop Services Store) is a hidden binary file macOS Finder creates in every directory you browse. It stores per-folder display preferences: icon positions, window size, view mode, sort order, and more.

The file uses a proprietary binary format built on a **Bud1 buddy allocator** managing a **B-tree** of records. Each record ties a filename to a property (icon position, modification date, view settings, etc.).

## Forensic value

`.DS_Store` files are useful artifacts in digital forensics because they:

- **Prove a directory was opened in Finder** - the file's existence means someone browsed that folder
- **Reveal deleted file references** - filenames persist in `.DS_Store` even after the files themselves are deleted, until the system reboots
- **Preserve Trash history** - records like `ptbN` (original filename) and `ptbL` (original path) show where trashed files came from, surviving even after the Trash is emptied
- **Record timestamps** - `modD`/`moDD` records store when Finder last saw a file's modification date
- **Show file sizes** - `lg1S`/`ph1S` capture logical and physical sizes at the time Finder indexed them
- **Contain directory structure clues** - filenames of subdirectories, files, and their metadata reveal what existed in a directory

Key locations to check:
- `~/.Trash/.DS_Store` - traces of deleted files and their original paths
- Any directory's `.DS_Store` - proves what files were present

## Usage

```
python3 ds_store_parser.py <.DS_Store file>
python3 ds_store_parser.py -o output.csv <.DS_Store file>
python3 ds_store_parser.py --json <.DS_Store file>
python3 ds_store_parser.py --raw <.DS_Store file>
```

| Flag | Description |
|------|-------------|
| `-o FILE` | Write output to file instead of stdout |
| `--json` | Output JSON instead of CSV |
| `--raw` | Add a `raw_hex` column with hex-encoded blob data |

A summary line prints to stderr: `parsed N records for M files/directories`

## Output format

CSV columns (or JSON keys):

| Column | Description |
|--------|-------------|
| `filename` | The file or directory name this record describes (`.` = the directory itself) |
| `record_type` | 4-character property code (see table below) |
| `data_type` | Storage type: `blob`, `long`, `comp`, `bool`, `ustr`, `type`, `shor`, `dutc` |
| `value` | Parsed, human-readable value |
| `detail` | What the property means |

## Record types

### Forensically significant

| Code | Description | Example value |
|------|-------------|---------------|
| `ptbN` | Original filename before Trash | `report.pdf` |
| `ptbL` | Original directory path before Trash | `System/Volumes/Data/Users/john/Desktop/` |
| `modD` / `moDD` | Modification timestamp (CFAbsoluteTime) | `2024-11-09T23:03:44.260570+00:00` |
| `lg1S` / `logS` | Logical file size | `163368089342 (152.1 GB)` |
| `ph1S` / `phyS` | Physical file size | `163385491456 (152.2 GB)` |

### File/directory display

| Code | Description | Example value |
|------|-------------|---------------|
| `Iloc` | Icon position | `x=340, y=252` |
| `dilc` | Desktop icon position | `x=0, y=65536 (+desktop flags)` |
| `vstl` | View style | `icon view`, `list view`, `column view`, `gallery view` |
| `dscl` | Expanded in list view | `True` / `False` |
| `cmmt` | Spotlight comment | free text |
| `extn` | File extension | `pdf` |

### Window/view settings

| Code | Description |
|------|-------------|
| `bwsp` | Window size, position, toolbar/sidebar state (decoded plist) |
| `fwi0` | Legacy Finder window rect + view type |
| `fwsw` | Sidebar width in pixels |
| `fwvh` | Window height |
| `icvp` | Icon view settings: icon size, grid, background, sort (decoded plist) |
| `icvt` | Icon view text size in points |
| `lsvp` / `lsvP` / `lsvC` | List view settings: columns, widths, sort order (decoded plist) |
| `lsvt` | List view text size in points |
| `BKGD` | Background type: `default`, `color: rgb(R,G,B)`, or `picture` |
| `pBBk` | Bookmark data blob |
| `pict` | Background picture alias record |
| `vSrn` | Version indicator (always `1`) |
| `ICVO` / `LSVO` | Icon/list view options enabled flag |
| `icgo` / `icsp` / `lssp` | Icon options, scroll positions |

## Testing and validation

This parser was validated against **368 real `.DS_Store` files** from my live macOS system, successfully parsing **7,320 records** with zero errors.

Validation covered:
- All 18 property codes encountered in the wild (`Iloc`, `lg1S`, `modD`, `ph1S`, `moDD`, `vSrn`, `bwsp`, `icvp`, `pBBk`, `dilc`, `dscl`, `lsvp`, `lsvC`, `ptbL`, `ptbN`, `vstl`, `lsvP`, `GRP0`)
- CFAbsoluteTime timestamp decoding verified against known file modification dates
- CSV output validated with Python's `csv.reader` (consistent column counts, proper quoting)
- JSON output validated with `json.tool`
- Trash put-back records (`ptbN`/`ptbL`) confirmed to contain real original filenames and paths
- Files ranging from small (4 records) to large (135+ records) with multi-level B-trees

## How it parses the binary format

1. **Header** - verifies `0x00000001` magic + `Bud1` allocator signature
2. **Buddy allocator** - reads the block address table and table of contents from the bookkeeping block
3. **B-tree** - locates the root node via the `DSDB` TOC entry, then recursively traverses internal and leaf nodes
4. **Records** - each B-tree entry contains a UTF-16BE filename, a 4-byte property code, a 4-byte type tag, and a type-dependent payload
5. **Interpretation** - timestamps are decoded from CFAbsoluteTime (float64 seconds since 2001-01-01), embedded binary plists are expanded, sizes are formatted, coordinates are extracted
