# DepCheck

A CLI tool to check dependency versions across different package ecosystems.

## Installation

```bash
go install github.com/harekrishnarai/depcheck@latest
```

## Usage

### Check a single package version

```bash
depcheck check express@4.18.2
```

### Check dependencies from a package file

```bash
depcheck file package.json
```

## Supported Package Files

- Node.js (package.json)
- Python (requirements.txt)
- More coming soon...

## Features

- Check if specific package versions exist
- Bulk check dependencies from package files
- Support for multiple package ecosystems
- Detailed version information

## Development

To build and run locally:

```bash
go build
./depcheck --help
``` 