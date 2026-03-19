#!/usr/bin/env python3
"""
ds_store_parser.py - macOS .DS_Store file parser for forensic analysis.

Parses the binary .DS_Store format (Bud1 buddy allocator + B-tree) and
extracts all Finder metadata records with human-readable interpretation.

Output: CSV or JSON with columns:
  filename, record_type, data_type, value, detail

Usage:
  python3 ds_store_parser.py <.DS_Store file>
  python3 ds_store_parser.py -o output.csv <.DS_Store file>
  python3 ds_store_parser.py --json <.DS_Store file>
  python3 ds_store_parser.py --raw <.DS_Store file>   # include hex blobs
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import plistlib
import struct
import sys
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Seconds between Mac epoch (1904-01-01) and Unix epoch (1970-01-01)
MAC_EPOCH_OFFSET = 2082844800

# dutc timestamps use 1/65536 second resolution
DUTC_DIVISOR = 65536

# CFAbsoluteTime epoch: 2001-01-01 00:00:00 UTC
CF_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# View style FourCC codes
VIEW_STYLES = {
    "icnv": "icon view",
    "clmv": "column view",
    "Nlsv": "list view",
    "Flwv": "gallery view",
    "glyv": "gallery view",
}

# Human-readable descriptions for each known property code
PROPERTY_DESCRIPTIONS = {
    "BKGD": "folder background type",
    "bwsp": "window size/position (plist)",
    "cmmt": "Spotlight comment",
    "dilc": "desktop icon location",
    "dscl": "sub-directory disclosed in list view",
    "extn": "file extension",
    "fwi0": "Finder window info",
    "fwsw": "Finder sidebar width (px)",
    "fwvh": "Finder window height",
    "GRP0": "group info",
    "icgo": "icon view options",
    "ICVO": "icon view enabled",
    "icsp": "icon view scroll position",
    "icvo": "icon view options (legacy)",
    "icvp": "icon view settings (plist)",
    "icvt": "icon view text size (pt)",
    "Iloc": "icon location",
    "info": "unknown info record",
    "lg1S": "logical size (bytes)",
    "logS": "logical size (bytes)",
    "lssp": "list view scroll position",
    "LSVO": "list view options enabled",
    "lsvo": "list view options (legacy)",
    "lsvC": "list view column settings (plist)",
    "lsvp": "list view settings (plist)",
    "lsvP": "list view settings (plist, variant)",
    "lsvt": "list view text size (pt)",
    "modD": "modification date",
    "moDD": "modification date",
    "ph1S": "physical size (bytes)",
    "phyS": "physical size (bytes)",
    "pBBk": "bookmark data",
    "pict": "background picture alias",
    "ptbL": "Trash put-back location",
    "ptbN": "Trash original path",
    "sr2c": "sort order 2 cache",
    "term": "terminal command",
    "vSrn": "version indicator",
    "vstl": "view style",
    "clip": "text clipping",
    "fndr": "Finder info",
    "icvl": "icon view label",
}


# ---------------------------------------------------------------------------
# Binary Reader
# ---------------------------------------------------------------------------

class BinaryReader:
    """Minimal reader over a bytes buffer with big-endian helpers."""

    __slots__ = ("data", "pos", "length")

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.pos = offset
        self.length = len(data)

    def read(self, n: int) -> bytes:
        if self.pos + n > self.length:
            raise ValueError(
                f"read past end: pos={self.pos}, n={n}, length={self.length}"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_uint32(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def read_int32(self) -> int:
        return struct.unpack(">i", self.read(4))[0]

    def read_uint16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def read_int64(self) -> int:
        return struct.unpack(">q", self.read(8))[0]

    def read_uint64(self) -> int:
        return struct.unpack(">Q", self.read(8))[0]

    def read_fourcc(self) -> str:
        return self.read(4).decode("ascii", errors="replace")

    def read_utf16be(self, char_count: int) -> str:
        return self.read(char_count * 2).decode("utf-16-be")

    def skip(self, n: int) -> None:
        self.pos += n

    def remaining(self) -> int:
        return self.length - self.pos


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class DSStoreRecord:
    filename: str
    property_code: str
    data_type: str
    raw_value: object  # type-dependent: int, str, bytes, bool, etc.


# ---------------------------------------------------------------------------
# Timestamp Helpers
# ---------------------------------------------------------------------------

def dutc_to_datetime(raw: int) -> datetime | None:
    """Convert a dutc (Mac epoch, 1/65536s resolution) value to datetime."""
    if raw == 0:
        return None
    try:
        seconds_since_mac = raw / DUTC_DIVISOR
        seconds_since_unix = seconds_since_mac - MAC_EPOCH_OFFSET
        return datetime.fromtimestamp(seconds_since_unix, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def cfabstime_to_datetime(data: bytes) -> datetime | None:
    """Convert 8-byte little-endian float64 CFAbsoluteTime to datetime.

    CFAbsoluteTime is seconds since 2001-01-01 00:00:00 UTC.
    Modern macOS stores modD/moDD as blob containing this format.
    """
    if len(data) < 8:
        return None
    try:
        seconds = struct.unpack("<d", data[:8])[0]
        if seconds == 0.0:
            return None
        return CF_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, ValueError, OSError):
        return None


def format_size(n: int) -> str:
    """Format byte count as human-readable size."""
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# Plist Decoder
# ---------------------------------------------------------------------------

def try_decode_plist(data: bytes) -> dict | list | str | None:
    """Attempt to decode a binary plist from blob data."""
    if not data.startswith(b"bplist"):
        return None
    try:
        return plistlib.loads(data)
    except Exception:
        return None


def plist_to_str(obj: object) -> str:
    """Flatten a plist object into a compact string representation."""
    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            parts.append(f"{k}={plist_to_str(v)}")
        return "{" + ", ".join(parts) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ", ".join(plist_to_str(v) for v in obj) + "]"
    if isinstance(obj, bytes):
        if len(obj) <= 16:
            return obj.hex()
        return obj[:16].hex() + f"...({len(obj)}B)"
    if isinstance(obj, datetime):
        return obj.isoformat()
    return repr(obj)


# ---------------------------------------------------------------------------
# Record Interpretation
# ---------------------------------------------------------------------------

def interpret_record(rec: DSStoreRecord) -> tuple[str, str]:
    """
    Return (value_str, detail_str) for a parsed record.
    value_str  = parsed/formatted value
    detail_str = human-readable description
    """
    code = rec.property_code
    dtype = rec.data_type
    val = rec.raw_value
    desc = PROPERTY_DESCRIPTIONS.get(code, f"unknown property '{code}'")

    match code:
        # --- Icon Location ---
        case "Iloc" if isinstance(val, bytes) and len(val) >= 16:
            x, y = struct.unpack(">II", val[:8])
            # bytes 8-15 are padding (0xFFFF... + 0x0000)
            return f"x={x}, y={y}", desc

        # --- Desktop Icon Location ---
        case "dilc" if isinstance(val, bytes) and len(val) >= 32:
            # First 16 bytes similar to Iloc, rest is desktop-specific
            x, y = struct.unpack(">II", val[:8])
            return f"x={x}, y={y} (+desktop flags)", desc

        # --- Background ---
        case "BKGD" if isinstance(val, bytes) and len(val) >= 12:
            bg_type = val[:4].decode("ascii", errors="replace")
            match bg_type:
                case "DefB":
                    return "default background", desc
                case "ClrB":
                    r, g, b = struct.unpack(">HHH", val[4:10])
                    return f"color: rgb({r},{g},{b})", desc
                case "PctB":
                    return "picture background", desc
                case _:
                    return f"type={bg_type} data={val[4:].hex()}", desc

        # --- Finder Window Info ---
        case "fwi0" if isinstance(val, bytes) and len(val) >= 16:
            top, left, bottom, right = struct.unpack(">HHHH", val[:8])
            view_code = val[8:12].decode("ascii", errors="replace")
            view_name = VIEW_STYLES.get(view_code, view_code)
            return (
                f"rect({top},{left},{bottom},{right}) view={view_name}",
                desc,
            )

        # --- View Style ---
        case "vstl" if isinstance(val, str) and len(val) == 4:
            view_name = VIEW_STYLES.get(val, val)
            return view_name, desc

        # --- Plist Properties ---
        case "bwsp" | "icvp" | "lsvp" | "lsvP" | "lsvC" if isinstance(val, bytes):
            plist = try_decode_plist(val)
            if plist is not None:
                return plist_to_str(plist), desc
            return f"blob({len(val)}B)", desc

        # --- Timestamps (dutc int format) ---
        case "modD" | "moDD" if isinstance(val, int):
            dt = dutc_to_datetime(val)
            if dt:
                return dt.isoformat(), desc
            return str(val), desc

        # --- Timestamps (blob format: CFAbsoluteTime, LE float64) ---
        case "modD" | "moDD" if isinstance(val, bytes):
            dt = cfabstime_to_datetime(val)
            if dt:
                return dt.isoformat(), desc
            return val.hex(), desc

        # --- Logical / Physical Sizes ---
        case "logS" | "lg1S" | "phyS" | "ph1S" if isinstance(val, int):
            return f"{val} ({format_size(val)})", desc

        # --- Text Sizes ---
        case "icvt" | "lsvt" | "fwvh" if isinstance(val, int):
            return str(val), desc

        # --- Sidebar Width ---
        case "fwsw" if isinstance(val, int):
            return f"{val}px", desc

        # --- Booleans ---
        case "ICVO" | "LSVO" | "dscl" if isinstance(val, (bool, int)):
            return str(bool(val)), desc

        # --- String Properties ---
        case "cmmt" | "extn" | "ptbN" | "GRP0" if isinstance(val, str):
            return val, desc

        # --- Trash Put-back Location (can be ustr or long) ---
        case "ptbL" if isinstance(val, str):
            return val, desc
        case "ptbL" if isinstance(val, int):
            return str(val), desc

        # --- Version ---
        case "vSrn" if isinstance(val, int):
            return str(val), desc

        # --- Icon View Options (legacy) ---
        case "icvo" if isinstance(val, bytes):
            if len(val) >= 18:
                # 4-byte "icvo" prefix, flags, size bytes
                label = val[:4].decode("ascii", errors="replace")
                return f"prefix={label} data={val[4:].hex()}", desc
            return val.hex(), desc

        # --- List View Options (legacy) ---
        case "lsvo" if isinstance(val, bytes):
            return f"blob({len(val)}B) {val[:8].hex()}...", desc

        # --- Scroll Positions ---
        case "icsp" | "lssp" if isinstance(val, bytes):
            if len(val) >= 8:
                x, y = struct.unpack(">II", val[:8])
                return f"scroll_x={x}, scroll_y={y}", desc
            return val.hex(), desc

        # --- Icon Options ---
        case "icgo" if isinstance(val, bytes):
            return val.hex(), desc

        # --- Info Record ---
        case "info" if isinstance(val, bytes):
            # First 8 bytes may be a dutc timestamp
            if len(val) >= 8:
                raw_ts = struct.unpack(">Q", val[:8])[0]
                dt = dutc_to_datetime(raw_ts)
                if dt:
                    return f"timestamp={dt.isoformat()} +{val[8:].hex()}", desc
            return val.hex(), desc

        # --- Background Picture (Alias) ---
        case "pict" if isinstance(val, bytes):
            return f"alias_record({len(val)}B)", desc

    # --- Fallback ---
    if isinstance(val, bytes):
        plist = try_decode_plist(val)
        if plist is not None:
            return plist_to_str(plist), desc
        if len(val) <= 64:
            return val.hex(), desc
        return f"blob({len(val)}B) {val[:32].hex()}...", desc
    if isinstance(val, int):
        return str(val), desc
    if isinstance(val, bool):
        return str(val), desc
    if isinstance(val, str):
        return val, desc
    return repr(val), desc


# ---------------------------------------------------------------------------
# .DS_Store Parser
# ---------------------------------------------------------------------------

class DSStoreParser:
    """
    Parses a .DS_Store file and yields DSStoreRecord objects.

    File layout:
      [4 bytes: 0x00000001]
      [Bud1 header: magic + allocator bookkeeping offset/size]
      [... buddy allocator managed blocks ...]
        -> TOC entry "DSDB" points to B-tree header
        -> B-tree nodes contain records
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.reader = BinaryReader(data)
        self.block_addresses: list[int] = []
        self.toc: dict[str, int] = {}
        self._parse_header()

    def _parse_header(self) -> None:
        """Parse file header and buddy allocator bookkeeping."""
        r = self.reader

        # File header: first 4 bytes must be 0x00000001
        magic1 = r.read_uint32()
        if magic1 != 1:
            raise ValueError(f"bad file magic: expected 0x00000001, got {magic1:#010x}")

        # Buddy allocator header
        magic2 = r.read(4)
        if magic2 != b"Bud1":
            raise ValueError(f"bad allocator magic: expected 'Bud1', got {magic2!r}")

        bk_offset = r.read_uint32()
        bk_size = r.read_uint32()
        bk_offset2 = r.read_uint32()
        if bk_offset != bk_offset2:
            warnings.warn(
                f"bookkeeping offset mismatch: {bk_offset} != {bk_offset2}"
            )

        # Skip 16 reserved bytes
        r.skip(16)

        # Read the bookkeeping block (offset is relative to start of data area,
        # which begins 4 bytes into the file, past the initial 0x00000001)
        bk_start = bk_offset + 4
        bk = BinaryReader(self.data[bk_start : bk_start + bk_size])

        # Block address table
        block_count = bk.read_uint32()
        bk.skip(4)  # 4 unknown/reserved bytes

        self.block_addresses = []
        for _ in range(block_count):
            self.block_addresses.append(bk.read_uint32())

        # Padding: table is padded to next multiple of 256 entries (1024 bytes)
        total_slots = ((block_count + 255) // 256) * 256
        remaining_slots = total_slots - block_count
        bk.skip(remaining_slots * 4)

        # Table of contents
        toc_count = bk.read_uint32()
        self.toc = {}
        for _ in range(toc_count):
            name_len = struct.unpack(">B", bk.read(1))[0]
            name = bk.read(name_len).decode("ascii")
            block_id = bk.read_uint32()
            self.toc[name] = block_id

        # Freelists (32 of them) - read but don't store, just validate
        for _ in range(32):
            fl_count = bk.read_uint32()
            bk.skip(fl_count * 4)

    def _get_block_data(self, block_id: int) -> bytes:
        """Get the raw bytes for a block given its ID."""
        if block_id >= len(self.block_addresses):
            raise ValueError(
                f"block ID {block_id} out of range (max {len(self.block_addresses) - 1})"
            )
        addr = self.block_addresses[block_id]
        offset = (addr >> 5) << 5
        size = 1 << (addr & 0x1F)
        # +4 for file header (past the initial 0x00000001)
        start = offset + 4
        return self.data[start : start + size]

    def _read_record(self, r: BinaryReader) -> DSStoreRecord:
        """Read a single record from the current position in a node."""
        # Filename
        name_len = r.read_uint32()
        filename = r.read_utf16be(name_len)

        # Property code (FourCC)
        property_code = r.read_fourcc()

        # Data type (FourCC)
        data_type = r.read_fourcc()

        # Value (depends on data type)
        match data_type:
            case "bool":
                raw_value = bool(struct.unpack(">B", r.read(1))[0])
            case "long":
                raw_value = r.read_uint32()
            case "shor":
                r.skip(2)  # 2 padding bytes
                raw_value = r.read_uint16()
            case "type":
                raw_value = r.read_fourcc()
            case "comp":
                raw_value = r.read_int64()
            case "dutc":
                raw_value = r.read_uint64()
            case "blob":
                blob_len = r.read_uint32()
                raw_value = r.read(blob_len)
            case "ustr":
                str_len = r.read_uint32()
                raw_value = r.read_utf16be(str_len)
            case _:
                warnings.warn(f"unknown data type '{data_type}' for {filename}/{property_code}")
                raw_value = None

        return DSStoreRecord(
            filename=filename,
            property_code=property_code,
            data_type=data_type,
            raw_value=raw_value,
        )

    def _traverse_node(self, block_id: int) -> list[DSStoreRecord]:
        """Recursively traverse a B-tree node, returning all records in order."""
        block_data = self._get_block_data(block_id)
        r = BinaryReader(block_data)

        p = r.read_uint32()  # child pointer (0 = leaf)
        count = r.read_uint32()  # number of records

        records: list[DSStoreRecord] = []

        if p == 0:
            # Leaf node: just read count records
            for _ in range(count):
                try:
                    records.append(self._read_record(r))
                except Exception as e:
                    warnings.warn(f"error reading record in leaf node (block {block_id}): {e}")
                    break
        else:
            # Internal node: P is the rightmost child block number.
            # Each record is preceded by a left child pointer.
            # Layout: [P | count | child_0, rec_0, child_1, rec_1, ..., child_{n-1}, rec_{n-1}]
            # Then P is traversed as the rightmost child after all records.
            for _ in range(count):
                child_id = r.read_uint32()
                records.extend(self._traverse_node(child_id))
                try:
                    records.append(self._read_record(r))
                except Exception as e:
                    warnings.warn(f"error reading record in internal node (block {block_id}): {e}")
                    break
            # Rightmost child
            records.extend(self._traverse_node(p))

        return records

    def parse(self) -> list[DSStoreRecord]:
        """Parse the entire .DS_Store file and return all records."""
        if "DSDB" not in self.toc:
            raise ValueError("no DSDB entry in table of contents")

        # Read B-tree header from the DSDB block
        dsdb_data = self._get_block_data(self.toc["DSDB"])
        dsdb = BinaryReader(dsdb_data)

        root_block_id = dsdb.read_uint32()
        levels = dsdb.read_uint32()       # tree height - 1
        record_count = dsdb.read_uint32()  # total records
        node_count = dsdb.read_uint32()    # total nodes
        page_size = dsdb.read_uint32()     # always 0x1000

        records = self._traverse_node(root_block_id)

        if len(records) != record_count:
            warnings.warn(
                f"record count mismatch: header says {record_count}, "
                f"parsed {len(records)}"
            )

        return records


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def records_to_csv(
    records: list[DSStoreRecord],
    output: io.TextIOBase,
    include_raw: bool = False,
) -> None:
    """Write records as CSV."""
    fieldnames = ["filename", "record_type", "data_type", "value", "detail"]
    if include_raw:
        fieldnames.append("raw_hex")

    writer = csv.writer(output)
    writer.writerow(fieldnames)

    for rec in records:
        value_str, detail_str = interpret_record(rec)
        row = [rec.filename, rec.property_code, rec.data_type, value_str, detail_str]
        if include_raw:
            if isinstance(rec.raw_value, bytes):
                row.append(rec.raw_value.hex())
            elif isinstance(rec.raw_value, int) and rec.data_type == "dutc":
                row.append(f"{rec.raw_value:016x}")
            else:
                row.append("")
        writer.writerow(row)


def records_to_json(
    records: list[DSStoreRecord],
    output: io.TextIOBase,
    include_raw: bool = False,
) -> None:
    """Write records as JSON."""
    entries = []
    for rec in records:
        value_str, detail_str = interpret_record(rec)
        entry = {
            "filename": rec.filename,
            "record_type": rec.property_code,
            "data_type": rec.data_type,
            "value": value_str,
            "detail": detail_str,
        }
        if include_raw and isinstance(rec.raw_value, bytes):
            entry["raw_hex"] = rec.raw_value.hex()
        entries.append(entry)

    json.dump(entries, output, indent=2, ensure_ascii=False)
    output.write("\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse macOS .DS_Store files and extract forensic metadata.",
        epilog="Outputs CSV by default. Use --json for JSON output.",
    )
    parser.add_argument("input", help="path to .DS_Store file")
    parser.add_argument(
        "-o", "--output",
        help="output file path (default: stdout)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="include raw hex column for blob values",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="use_json",
        help="output JSON instead of CSV",
    )
    args = parser.parse_args()

    # Read input file
    try:
        with open(args.input, "rb") as f:
            data = f.read()
    except (OSError, IOError) as e:
        print(f"error: cannot read '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)

    if len(data) < 36:
        print(f"error: file too small to be a .DS_Store ({len(data)} bytes)", file=sys.stderr)
        sys.exit(1)

    # Parse
    try:
        ds = DSStoreParser(data)
        records = ds.parse()
    except (ValueError, struct.error) as e:
        print(f"error: failed to parse '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)

    # Output
    if args.output:
        out = open(args.output, "w", newline="", encoding="utf-8")
    else:
        out = sys.stdout

    try:
        if args.use_json:
            records_to_json(records, out, include_raw=args.raw)
        else:
            records_to_csv(records, out, include_raw=args.raw)
    finally:
        if args.output:
            out.close()

    # Summary to stderr
    unique_files = {r.filename for r in records}
    print(
        f"parsed {len(records)} records for {len(unique_files)} files/directories",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
