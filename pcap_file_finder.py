#!/usr/bin/env python3

import argparse
import ipaddress
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
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_QINQ = 0x9100
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


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


def parse_ip_address(value):
    """Parse and validate IPv4/IPv6 address input."""
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "invalid IP address. Use a valid IPv4 or IPv6 address"
        ) from exc


def _packet_datetime(seconds_float):
    try:
        return datetime.fromtimestamp(seconds_float)
    except (OverflowError, OSError, ValueError):
        return None


def _ip_match_ipv4(payload, target_ip):
    if len(payload) < 20:
        return False
    try:
        src_ip = ipaddress.ip_address(payload[12:16])
        dst_ip = ipaddress.ip_address(payload[16:20])
    except ValueError:
        return False
    return src_ip == target_ip or dst_ip == target_ip


def _ip_match_ipv6(payload, target_ip):
    if len(payload) < 40:
        return False
    try:
        src_ip = ipaddress.ip_address(payload[8:24])
        dst_ip = ipaddress.ip_address(payload[24:40])
    except ValueError:
        return False
    return src_ip == target_ip or dst_ip == target_ip


def _packet_contains_ip(packet_data, linktype, target_ip):
    if target_ip is None:
        return True

    if linktype == DLT_RAW:
        if len(packet_data) < 1:
            return False
        version = packet_data[0] >> 4
        if version == 4:
            return _ip_match_ipv4(packet_data, target_ip)
        if version == 6:
            return _ip_match_ipv6(packet_data, target_ip)
        return False

    if linktype == DLT_EN10MB:
        if len(packet_data) < 14:
            return False
        offset = 14
        ethertype = struct.unpack("!H", packet_data[12:14])[0]

        # Skip VLAN tags if present.
        while ethertype in (ETH_P_8021Q, ETH_P_8021AD, ETH_P_QINQ):
            if len(packet_data) < offset + 4:
                return False
            ethertype = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
            offset += 4

        payload = packet_data[offset:]
        if ethertype == ETH_P_IP:
            return _ip_match_ipv4(payload, target_ip)
        if ethertype == ETH_P_IPV6:
            return _ip_match_ipv6(payload, target_ip)
        return False

    if linktype == DLT_LINUX_SLL:
        if len(packet_data) < 16:
            return False
        ethertype = struct.unpack("!H", packet_data[14:16])[0]
        payload = packet_data[16:]
        if ethertype == ETH_P_IP:
            return _ip_match_ipv4(payload, target_ip)
        if ethertype == ETH_P_IPV6:
            return _ip_match_ipv6(payload, target_ip)
        return False

    if linktype == DLT_LINUX_SLL2:
        if len(packet_data) < 20:
            return False
        ethertype = struct.unpack("!H", packet_data[0:2])[0]
        payload = packet_data[20:]
        if ethertype == ETH_P_IP:
            return _ip_match_ipv4(payload, target_ip)
        if ethertype == ETH_P_IPV6:
            return _ip_match_ipv6(payload, target_ip)
        return False

    return False


def pcap_matches(file_path, begin_time, end_time, target_ip=None):
    """Return True if a classic PCAP file matches requested filters."""
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
        ip_match_in_window = False
        linktype = struct.unpack(f"{endian}I", remainder[16:20])[0]

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

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                return None
            if (
                target_ip is not None
                and begin_time <= timestamp <= end_time
                and _packet_contains_ip(packet_data, linktype, target_ip)
            ):
                ip_match_in_window = True

        if first_ts is None:
            return None

        if target_ip is not None:
            return ip_match_in_window

        return first_ts <= end_time and begin_time <= last_ts


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


def pcapng_matches(file_path, begin_time, end_time, target_ip=None):
    """Return True if a PCAPNG file matches requested filters."""
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
        interface_linktypes = []
        ip_match_in_window = False

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
                linktype = struct.unpack(f"{endian}H", body[0:2])[0]
                options = body[8:]
                interface_linktypes.append(linktype)
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
                if target_ip is not None:
                    cap_len = struct.unpack(f"{endian}I", body[12:16])[0]
                    if len(body) < 20 + cap_len:
                        return None
                    packet_data = body[20 : 20 + cap_len]
                    linktype = (
                        interface_linktypes[interface_id]
                        if interface_id < len(interface_linktypes)
                        else None
                    )
                    if (
                        linktype is not None
                        and begin_time <= timestamp <= end_time
                        and _packet_contains_ip(packet_data, linktype, target_ip)
                    ):
                        ip_match_in_window = True
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
                if target_ip is not None:
                    cap_len = struct.unpack(f"{endian}I", body[12:16])[0]
                    if len(body) < 20 + cap_len:
                        return None
                    packet_data = body[20 : 20 + cap_len]
                    linktype = (
                        interface_linktypes[interface_id]
                        if interface_id < len(interface_linktypes)
                        else None
                    )
                    if (
                        linktype is not None
                        and begin_time <= timestamp <= end_time
                        and _packet_contains_ip(packet_data, linktype, target_ip)
                    ):
                        ip_match_in_window = True

        if first_ts is None:
            return None

        if target_ip is not None:
            return ip_match_in_window

        return first_ts <= end_time and begin_time <= last_ts


def capture_matches(file_path, begin_time, end_time, target_ip=None):
    with file_path.open("rb") as f:
        signature = f.read(4)

    if signature in PCAP_MAGICS:
        return pcap_matches(file_path, begin_time, end_time, target_ip)
    if signature == PCAPNG_MAGIC:
        return pcapng_matches(file_path, begin_time, end_time, target_ip)
    return None


def find_pcap_files(directory, begin_time, end_time, target_ip=None):
    matching_files = []

    for entry in sorted(directory.iterdir()):
        if not entry.is_file():
            continue

        is_match = capture_matches(entry, begin_time, end_time, target_ip)
        if is_match is None:
            continue

        if is_match:
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
            "  pcap_file_finder.py -d ./captures -b '2026-02-15 10:00:00' -e '2026-02-15 11:00:00' --ip 2001:db8::1\n"
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
    parser.add_argument(
        "--ip",
        type=parse_ip_address,
        help=(
            "Only match files containing packets within the time window where "
            "source or destination IP equals this IPv4/IPv6 address"
        ),
    )

    args = parser.parse_args()

    if not args.directory.is_dir():
        parser.error(f"directory does not exist or is not a directory: {args.directory}")
    if args.begin > args.end:
        parser.error("--begin must be earlier than or equal to --end")

    matching_files = find_pcap_files(args.directory, args.begin, args.end, args.ip)

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
