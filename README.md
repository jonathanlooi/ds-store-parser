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
```

| Flag | Description |
|------|-------------|
| `-o FILE` | Write output to file instead of stdout |
| `--json` | Output JSON instead of CSV |

A summary line prints to stderr: `parsed N records for M files/directories`

## Output format

The output has **one row per file or folder** referenced in the `.DS_Store`. Each row consolidates all the raw binary records for that entry into human-readable columns.

| Column | What it tells you |
|--------|-------------------|
| `path` | Full filesystem path of the file/folder (inferred from the .DS_Store location) |
| `name` | Filename or folder name |
| `type` | `file`, `folder`, `this directory` (the folder the .DS_Store lives in), or `file or folder` (ambiguous - Finder indexed it but never opened it) |
| `logical_size` | Human-readable file/folder size (e.g. `152.1 GB`) |
| `logical_size_bytes` | Exact size in bytes |
| `physical_size` | Disk space used (accounts for block size overhead) |
| `physical_size_bytes` | Exact physical size in bytes |
| `modification_date` | ISO 8601 timestamp of when Finder last recorded the modification date |
| `was_on_desktop` | `yes` if this item had a desktop icon position stored |
| `icon_location` | Finder icon x,y coordinates |
| `view_style` | How Finder displayed this folder: `icon view`, `list view`, `column view`, `gallery view` |
| `folder_window_bounds` | Finder window position/size when this folder was open |
| `spotlight_comment` | User-set Spotlight comment text |
| `trash_original_name` | If this file was trashed: what it was originally called |
| `trash_original_path` | If this file was trashed: the directory it lived in before deletion |
| `expanded_in_list_view` | Whether this subfolder was expanded in its parent's list view |
| `raw_records` | JSON array of all raw parsed records for this entry (property codes, types, values, hex data) |

### How to read the type column

- **`file`** - This was a file (had an icon position, desktop placement, extension, or trash record)
- **`folder`** - This was a folder that someone opened in Finder (it has window/view settings like window bounds, icon size, view style)
- **`this directory`** - Metadata about the directory the `.DS_Store` file lives in (its own window settings)
- **`file or folder`** - Finder recorded size/date metadata for this entry (from a parent directory listing) but it was never opened, so we can't tell if it's a file or folder

### Interpreting the trash columns

When a file is moved to Trash via Finder, the `.DS_Store` may record:
- `trash_original_name`: The file's name before it was trashed (it may have been renamed, e.g. a screenshot renamed to something shorter)
- `trash_original_path`: The full directory path where the file lived before deletion (e.g. `System/Volumes/Data/Users/john/Desktop/`)

These records can persist even after the Trash is emptied (until reboot), making them valuable for proving a file existed and was intentionally deleted.

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
6. **Collation** - multiple raw records for the same filename are grouped into a single row with clear column names
