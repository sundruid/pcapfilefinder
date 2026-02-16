# PCAP File Finder

`pcap_file_finder.py` is a command-line tool that scans capture files in a directory, finds files whose packet timestamps overlap a target time window, and optionally packages the matched files into a `.tar.gz` archive for transfer and later analysis (for example in Wireshark).

This is useful when you have many captures and need to quickly isolate only the files relevant to an incident or troubleshooting window.

## Features

- Supports **PCAP** and **PCAPNG** file formats by reading file content, not filename patterns.
- Filters files by **packet timestamp overlap** with a user-provided begin/end time.
- Accepts flexible time input:
  - `YYYY-MM-DD`
  - `YYYY-MM-DD HH:MM`
  - `YYYY-MM-DD HH:MM:SS`
  - Unix epoch timestamp (seconds)
- Creates a compressed archive with `--x` / `--extract`:
  - Builds `ARCHIVE_NAME.tar.gz` in the current working directory.
  - Includes only matched capture files.
- Uses only Python standard library modules (no external dependencies).

## How It Works

1. Iterates through regular files in the target directory.
2. Detects each file format using binary signatures (PCAP/PCAPNG).
3. Parses packet headers to determine each file's first and last packet timestamps.
4. Compares that range to your requested time window.
5. Prints matching filenames.
6. If `--x` is provided, packages matched files into a `.tar.gz`.

## Requirements

- Python 3.8+ recommended
- Linux/macOS/Windows environment with Python installed

## Usage

```bash
python3 pcap_file_finder.py -b BEGIN -e END -d DIRECTORY [--x ARCHIVE_NAME]
```

### Arguments

- `-b, --begin` (required)  
  Start of time window. Formats:
  - `YYYY-MM-DD`
  - `YYYY-MM-DD HH:MM`
  - `YYYY-MM-DD HH:MM:SS`
  - Unix epoch (e.g. `1707985200`)

- `-e, --end` (required)  
  End of time window. Same accepted formats as `--begin`.

- `-d, --directory` (required)  
  Directory containing capture files to inspect.

- `--x, --extract ARCHIVE_NAME` (optional)  
  Create `ARCHIVE_NAME.tar.gz` in the current local working directory.
  If you omit `.tar.gz`, it is automatically appended.

## Examples

### 1) Find captures in a date-time window

```bash
python3 pcap_file_finder.py \
  -d ./captures \
  -b "2026-02-15 10:00:00" \
  -e "2026-02-15 11:00:00"
```

### 2) Use Unix timestamps

```bash
python3 pcap_file_finder.py \
  --directory ./captures \
  --begin 1707985200 \
  --end 1707988800
```

### 3) Find and package matched captures for retrieval

```bash
python3 pcap_file_finder.py \
  -d ./captures \
  -b 1707985200 \
  -e 1707988800 \
  --x case_123_window
```

This creates:

- `./case_123_window.tar.gz` (in the current directory where the command is run)

You can then move this archive to another system and open the files in tools like Wireshark.

## Output Behavior

- If matches are found:
  - Prints `Matching files:`
  - Lists each filename
  - If extraction is requested, prints the created archive path
- If no matches are found:
  - Prints `No matching files found.`

## Notes and Limitations

- The tool reads packet metadata from capture files; it does not inspect protocol payload content.
- PCAPNG support is based on packet timestamp blocks and interface timestamp resolution handling.
- Files that are truncated or malformed may be skipped.
- Time interpretation uses the local system timezone behavior of Python `datetime.fromtimestamp()`.

## Troubleshooting

- **No files returned**
  - Confirm your time window is correct (`--begin` <= `--end`).
  - Verify files are valid PCAP/PCAPNG.
  - Try a wider time range.

- **Argument errors**
  - Check your datetime format or use Unix epoch timestamps.
  - Confirm `--directory` points to an existing directory.

- **Archive not created**
  - Archive is created only when matches exist and `--x` is supplied.
  - Ensure write permissions in your current working directory.

## Quick Help

```bash
python3 pcap_file_finder.py -h
```
