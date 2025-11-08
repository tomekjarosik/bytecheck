# ByteCheck

A powerful file integrity verification tool that generates cryptographically signed manifests for directories and their contents. ByteCheck ensures data integrity during file transfers and storage, inspired by ZFS scrubbing mechanisms but designed to be lightweight and portable.

## Features

- **Recursive manifest generation** - Creates integrity manifests for directory trees
- **Cryptographic verification** - Uses HMAC for tamper-proof manifests
- **Incremental processing** - Skip recently processed directories with freshness intervals
- **Cross-platform compatibility** - Works on any system where Go runs
- **Progress monitoring** - Real-time feedback during operations
- **Fast verification** - Quickly detect file changes, corruption, or missing files

## Installation
```bash
go install github.com/tomekjarosik/bytecheck@latest
```
Or build from source:
```bash
git clone https://github.com/tomekjarosik/bytecheck.git
cd bytecheck
go build -o bytecheck
sudo mv bytecheck /usr/local/bin/
```

## Quick Start

```bash
# Generate manifests
bytecheck generate /your/data

# Verify integrity
bytecheck verify /your/data

# Clean up manifests
bytecheck clean /your/data
```

## Configuration

ByteCheck uses reasonable default. If you want maximum security,
you can use custom HMAC key using this enviroment variable:

- `BYTECHECK_HMAC_KEY` - Secret key for manifest signing

## Commands

### Generate Manifests
```bash
bytecheck generate [directory]
```
Recursively generates `.bytecheck.manifest` files for each directory, containing checksums and metadata for all files.

**Options:**
- `--freshness-interval duration` - Skip directories with manifests newer than this interval (e.g., `5s`, `1m`, `24h`)

**Examples:**
```bash
# Generate manifests for current directory
bytecheck generate

# Generate manifests for specific directory
bytecheck generate /path/to/data

# Skip recently processed directories (within last hour)
bytecheck generate --freshness-interval 1h /path/to/data
```

### Verify Integrity
```bash
bytecheck verify [directory]
```
Recursively verifies all manifest files against current directory state. Detects:
- Modified files
- Missing files
- New files
- Corrupted manifests

**Options:**
- `--freshness-interval duration` - Reuse recent manifests instead of recalculating

**Examples:**
```bash
# Verify current directory
bytecheck verify

# Verify specific directory
bytecheck verify /path/to/data

# Use cached manifests from last 30 minutes
bytecheck verify --freshness-interval 30m /path/to/data
```
### Clean Manifests
```bash
bytecheck clean [directory]
```
Recursively removes all `.bytecheck.manifest` files from the directory tree.

**Example:**
```bash
# Remove all manifests from current directory
bytecheck clean

# Remove all manifests from specific directory
bytecheck clean /path/to/data
```
## Primary Use Cases

### 1. Data Transfer Verification
Perfect for ensuring data integrity when moving files between systems:
```bash
# Before copying to external drive
bytecheck generate /important/data

# After copying to new location
bytecheck verify /backup/important/data
```
### 2. Long-term Storage Monitoring
Regularly verify stored data hasn't been corrupted:
```bash
# Generate baselines
bytecheck generate /archive

# Monthly verification
bytecheck verify /archive
```
### 3. Build System Integrity
Ensure source code and build artifacts remain unchanged:

```bash
# Baseline after clean checkout
bytecheck generate ./src

# Verify before important builds
bytecheck verify ./src
```

## Advanced Use Cases

### 4. Duplicate Directory Detection
Find identical directory structures by comparing manifest files:

```shell script
# Generate manifests for all directories
find /data -type d -exec bytecheck generate {} \;

# Find duplicate manifests (identical directories)
find /data -name ".bytecheck.manifest" -exec md5sum {} \; | sort | uniq -w32 -D
```


### 5. Incremental Backup Validation
Verify that incremental backups contain unchanged files:

```shell script
# Generate manifests for source
bytecheck generate /source/data

# After incremental backup, verify unchanged files
bytecheck verify /backup/incremental --freshness-interval 24h
```


### 6. Content Distribution Verification
Ensure distributed content matches the source:

```shell script
# At source
bytecheck generate /content/distribution

# At each destination
rsync -av source:/content/distribution/ ./local/content/
bytecheck verify ./local/content
```


### 7. Development Environment Consistency
Ensure development environments have identical file structures:

```shell script
# On reference environment
bytecheck generate /dev/environment

# On each developer machine
bytecheck verify /dev/environment
```


### 8. Digital Forensics and Chain of Custody
Maintain cryptographic proof of file integrity:

```shell script
# Initial evidence capture
bytecheck generate /evidence/case001

# Later verification
bytecheck verify /evidence/case001
# Any changes will be detected and reported
```


### 9. Configuration Management Auditing
Track changes to system configurations:

```shell script
# Baseline system configuration
bytecheck generate /etc
bytecheck generate /opt/app/config

# Regular audits
bytecheck verify /etc
bytecheck verify /opt/app/config
```


### 10. Archival Storage Validation
Verify long-term archives periodically:

```shell script
#!/bin/bash
# Monthly archive validation script
for archive in /archives/*/; do
    echo "Checking $archive"
    bytecheck verify "$archive"
done
```


## How It Works

1. **Generate**: ByteCheck walks through directories, calculates checksums for all files, and creates a manifest file with cryptographic signatures
2. **Verify**: Recalculates checksums and compares against stored manifests, detecting any discrepancies
3. **Clean**: Removes all generated manifest files from the directory tree

## Manifest Format

Manifest files (`.bytecheck.manifest`) contain:
- File/directory names and checksums
- Cryptographic HMAC for tamper detection
- Metadata for efficient verification

## Performance Tips

- Use `--freshness-interval` to skip recently processed directories
- ByteCheck is optimized for large directory trees
- Manifest files are small and don't significantly impact storage

## Security Notes

- Manifests use HMAC-SHA256 for tamper detection
- Each manifest includes a cryptographic signature using a secret key
- Without the key, manifests cannot be forged or modified without detection
- For maximum security, store the HMAC key separately from your data

## License

ByteCheck is licensed under the Apache 2.0 License. See the LICENSE file for details.

