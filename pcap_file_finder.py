#!/usr/bin/env python3

import argparse
import struct
import tarfile
from pathlib import Path
from datetime import datetime

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_SECTION_BOM_LE = b"\x4d\x3c\x2b\x1a"
PCAPNG_SECTION_BOM_BE = b"\x1a\x2b\x3c\x4d"


def parse_datetime(value):
    """Parse user-provided datetime or Unix timestamp."""
    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    )

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    # Also allow Unix timestamps to reduce formatting friction.
    try:
        return datetime.fromtimestamp(int(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "invalid datetime. Use 'YYYY-MM-DD HH:MM[:SS]' or Unix timestamp"
        ) from exc


def _packet_datetime(seconds_float):
    try:
        return datetime.fromtimestamp(seconds_float)
    except (OverflowError, OSError, ValueError):
        return None


def pcap_time_range(file_path):
    """Return (first_packet_time, last_packet_time) for classic PCAP files."""
    with file_path.open("rb") as f:
        magic = f.read(4)
        magic_info = PCAP_MAGICS.get(magic)
        if magic_info is None:
            return None

        endian, frac_base = magic_info

        # Read remaining bytes from the 24-byte global header.
        remainder = f.read(20)
        if len(remainder) != 20:
            return None

        first_ts = None
        last_ts = None

        while True:
            packet_header = f.read(16)
            if len(packet_header) == 0:
                break
            if len(packet_header) < 16:
                return None

            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                f"{endian}IIII", packet_header
            )
            timestamp = _packet_datetime(ts_sec + (ts_frac / frac_base))
            if timestamp is None:
                return None
            if first_ts is None:
                first_ts = timestamp
            last_ts = timestamp

            # Skip packet bytes.
            f.seek(incl_len, 1)

        if first_ts is None:
            return None
        return (first_ts, last_ts)


def _parse_pcapng_if_tsresol(options_bytes, endian):
    """Return seconds per timestamp unit from if_tsresol option, default microseconds."""
    idx = 0
    seconds_per_unit = 1e-6

    while idx + 4 <= len(options_bytes):
        opt_code, opt_len = struct.unpack(f"{endian}HH", options_bytes[idx : idx + 4])
        idx += 4
        if idx + opt_len > len(options_bytes):
            break

        opt_value = options_bytes[idx : idx + opt_len]
        padded_len = (opt_len + 3) & ~3
        idx += padded_len

        if opt_code == 0:
            break
        if opt_code != 9 or opt_len != 1:
            continue

        val = opt_value[0]
        if val & 0x80:
            exponent = val & 0x7F
            seconds_per_unit = 2 ** (-exponent)
        else:
            seconds_per_unit = 10 ** (-val)

    return seconds_per_unit


def pcapng_time_range(file_path):
    """Return (first_packet_time, last_packet_time) for PCAPNG files."""
    with file_path.open("rb") as f:
        block_header = f.read(8)
        if len(block_header) < 8 or block_header[0:4] != PCAPNG_MAGIC:
            return None

        section_bom = f.read(4)
        if section_bom == PCAPNG_SECTION_BOM_LE:
            endian = "<"
        elif section_bom == PCAPNG_SECTION_BOM_BE:
            endian = ">"
        else:
            return None

        first_block_len = struct.unpack(f"{endian}I", block_header[4:8])[0]
        if first_block_len < 12:
            return None

        # Skip the remainder of the Section Header Block (12 bytes consumed so far).
        remaining = first_block_len - 12
        if remaining < 0:
            return None
        f.seek(remaining, 1)

        first_ts = None
        last_ts = None
        interface_resolutions = []

        while True:
            hdr = f.read(8)
            if len(hdr) == 0:
                break
            if len(hdr) < 8:
                return None

            block_type, block_total_len = struct.unpack(f"{endian}II", hdr)
            if block_total_len < 12:
                return None

            body_len = block_total_len - 12
            body = f.read(body_len)
            if len(body) < body_len:
                return None

            trailer = f.read(4)
            if len(trailer) < 4:
                return None
            trailer_len = struct.unpack(f"{endian}I", trailer)[0]
            if trailer_len != block_total_len:
                return None

            # Interface Description Block: capture timestamp resolution option if present.
            if block_type == 0x00000001:
                if len(body) < 8:
                    return None
                options = body[8:]
                interface_resolutions.append(
                    _parse_pcapng_if_tsresol(options, endian)
                )
                continue

            # Enhanced Packet Block: interface_id, ts_high, ts_low, ...
            if block_type == 0x00000006:
                if len(body) < 20:
                    return None
                interface_id, ts_high, ts_low = struct.unpack(
                    f"{endian}III", body[0:12]
                )
                ts_units = (ts_high << 32) | ts_low
                resolution = (
                    interface_resolutions[interface_id]
                    if interface_id < len(interface_resolutions)
                    else 1e-6
                )
                timestamp = _packet_datetime(ts_units * resolution)
                if timestamp is None:
                    continue
                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp
                continue

            # Obsolete Packet Block: if_id+drop_count(4), ts_high, ts_low, ...
            if block_type == 0x00000002:
                if len(body) < 20:
                    return None
                interface_id = struct.unpack(f"{endian}H", body[0:2])[0]
                ts_high, ts_low = struct.unpack(f"{endian}II", body[4:12])
                ts_units = (ts_high << 32) | ts_low
                resolution = (
                    interface_resolutions[interface_id]
                    if interface_id < len(interface_resolutions)
                    else 1e-6
                )
                timestamp = _packet_datetime(ts_units * resolution)
                if timestamp is None:
                    continue
                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp

        if first_ts is None:
            return None
        return (first_ts, last_ts)


def capture_time_range(file_path):
    with file_path.open("rb") as f:
        signature = f.read(4)

    if signature in PCAP_MAGICS:
        return pcap_time_range(file_path)
    if signature == PCAPNG_MAGIC:
        return pcapng_time_range(file_path)
    return None


def find_pcap_files(directory, begin_time, end_time):
    matching_files = []

    for entry in sorted(directory.iterdir()):
        if not entry.is_file():
            continue

        time_range = capture_time_range(entry)
        if time_range is None:
            continue

        first_ts, last_ts = time_range
        # Match if file's packet-time window overlaps requested window.
        if first_ts <= end_time and begin_time <= last_ts:
            matching_files.append(entry.name)

    return matching_files


def create_archive(source_directory, filenames, archive_name):
    """Create a gzip-compressed tar archive in the current working directory."""
    base_name = Path(archive_name).name
    if not base_name:
        raise ValueError("archive name cannot be empty")

    if not base_name.endswith(".tar.gz"):
        base_name = f"{base_name}.tar.gz"

    archive_path = Path.cwd() / base_name
    with tarfile.open(archive_path, "w:gz") as tar:
        for filename in filenames:
            tar.add(source_directory / filename, arcname=filename)

    return archive_path


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Find files that are valid PCAP/PCAPNG and contain packets in a time range."
        ),
        epilog=(
            "Examples:\n"
            "  pcap_file_finder.py -d ./captures -b '2026-02-15 10:00:00' -e '2026-02-15 11:00:00'\n"
            "  pcap_file_finder.py --directory ./captures --begin 1707985200 --end 1707988800\n"
            "  pcap_file_finder.py -d ./captures -b 1707985200 -e 1707988800 --x selected_caps\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-b",
        "--begin",
        required=True,
        type=parse_datetime,
        help="Start time: YYYY-MM-DD HH:MM[:SS] or Unix timestamp",
    )
    parser.add_argument(
        "-e",
        "--end",
        required=True,
        type=parse_datetime,
        help="End time: YYYY-MM-DD HH:MM[:SS] or Unix timestamp",
    )
    parser.add_argument(
        "-d",
        "--directory",
        required=True,
        type=Path,
        help="Directory containing capture files (PCAP or PCAPNG format)",
    )
    parser.add_argument(
        "--x",
        "--extract",
        dest="extract",
        metavar="ARCHIVE_NAME",
        help=(
            "Create ARCHIVE_NAME.tar.gz in current directory with matched files "
            "(if .tar.gz is omitted, it is added automatically)"
        ),
    )

    args = parser.parse_args()

    if not args.directory.is_dir():
        parser.error(f"directory does not exist or is not a directory: {args.directory}")
    if args.begin > args.end:
        parser.error("--begin must be earlier than or equal to --end")

    matching_files = find_pcap_files(args.directory, args.begin, args.end)

    if matching_files:
        print("Matching files:")
        for file in matching_files:
            print(file)
        if args.extract:
            archive_path = create_archive(args.directory, matching_files, args.extract)
            print(f"\nCreated archive: {archive_path}")
    else:
        print("No matching files found.")

if __name__ == "__main__":
    main()
