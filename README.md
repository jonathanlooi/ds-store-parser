# .DS_Store Parser

A Python CLI tool that parses macOS `.DS_Store` files and outputs structured CSV or JSON for forensic analysis. No external dependencies. Python 3.10+.

## What is a .DS_Store file?

`.DS_Store` (Desktop Services Store) is a hidden binary file macOS Finder creates in every directory you browse. It uses a proprietary format built on a **Bud1 buddy allocator** managing a **B-tree** of records. Each record ties a filename to a property (icon position, modification date, view settings, etc.).

## Forensic value

- **Prove a directory was opened in Finder** - the file's existence means someone browsed that folder
- **Reveal deleted file references** - filenames persist even after the files are deleted (until reboot)
- **Preserve Trash history** - `ptbN`/`ptbL` records show original filenames and paths of trashed files, surviving even after Trash is emptied
- **Record timestamps and sizes** - `modD`/`moDD` store modification dates; `lg1S`/`ph1S` capture logical and physical sizes

Key locations: `~/.Trash/.DS_Store` for traces of deleted files, any directory's `.DS_Store` to prove what files were present.

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

One row per file or folder referenced in the `.DS_Store`. Each row consolidates all raw binary records for that entry into human-readable columns.

| Column | What it tells you |
|--------|-------------------|
| `path` | Full filesystem path (inferred from .DS_Store location) |
| `name` | Filename or folder name |
| `type` | `file`, `folder`, `this directory`, or `file or folder` (ambiguous) |
| `logical_size` | Human-readable size (e.g. `152.1 GB`) |
| `logical_size_bytes` | Exact size in bytes |
| `physical_size` | Disk space used (block size overhead) |
| `physical_size_bytes` | Exact physical size in bytes |
| `modification_date` | ISO 8601 timestamp from Finder |
| `was_on_desktop` | `yes` if item had a desktop icon position |
| `icon_location` | Finder icon x,y coordinates |
| `view_style` | `icon view`, `list view`, `column view`, or `gallery view` |
| `folder_window_bounds` | Finder window position/size |
| `spotlight_comment` | User-set Spotlight comment |
| `trash_original_name` | Original filename before trashing |
| `trash_original_path` | Directory the file lived in before deletion |
| `expanded_in_list_view` | Whether subfolder was expanded in list view |
| `raw_records` | JSON array of all raw parsed records (property codes, types, values, hex) |

### Type column

- **`file`** - Had icon position, desktop placement, extension, or trash record
- **`folder`** - Had window/view settings (window bounds, icon size, view style)
- **`this directory`** - Metadata about the directory the `.DS_Store` lives in
- **`file or folder`** - Only size/date metadata; never opened, so type is ambiguous

### Trash columns

`trash_original_name` and `trash_original_path` record where a file came from before it was moved to Trash. These persist even after Trash is emptied (until reboot), making them valuable for proving a file existed and was intentionally deleted.

## Testing

Validated against **368 real `.DS_Store` files** (7,320 records, zero errors). Covers all 18 property codes encountered in the wild, CFAbsoluteTime timestamp decoding, CSV/JSON output validation, trash put-back records, and B-trees ranging from 4 to 135+ records.

## How it parses the binary format

1. **Header** - verifies `0x00000001` magic + `Bud1` allocator signature
2. **Buddy allocator** - reads block address table and TOC from the bookkeeping block
3. **B-tree** - locates root node via `DSDB` TOC entry, recursively traverses internal and leaf nodes
4. **Records** - each entry contains a UTF-16BE filename, 4-byte property code, 4-byte type tag, and type-dependent payload
5. **Interpretation** - CFAbsoluteTime timestamps, binary plists, sizes, and coordinates decoded to human-readable values
6. **Collation** - multiple records per filename grouped into a single output row

## Credits

- [DS_Store File Format](https://wiki.mozilla.org/DS_Store_File_Format) - Mark Mentovai
- [DSStoreFormat.pod](https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod) - Wim Lewis
- [Parsing the .DS_Store file format](https://0day.work/parsing-the-ds_store-file-format/) - Sebastian Neef
