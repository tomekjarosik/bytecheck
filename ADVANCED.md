# Advanced Usage: Cryptographic Auditing

ByteCheck supports cryptographically signed manifests that provide verifiable proof of data integrity and origin. This advanced feature allows you to act as an **auditor** who can digitally sign directory structures.

## Auditor Concept

An **auditor** is a trusted entity that cryptographically signs directory manifests, providing:
- **Proof of origin** - Verifiable identity of who created the manifest
- **Tamper evidence** - Any modification to manifests is detectable
- **Trust chain** - Verification against trusted public keys (like GitHub keys)

## Generating Signed Manifests

### Prerequisites
- An SSH Ed25519 key pair
- Your public key uploaded to GitHub (for GitHub-based trust)

### Basic Usage
```bash
# Generate signed manifests using your SSH private key
bytecheck generate /your/data --private-key ~/.ssh/id_ed25519 --auditor-reference github:yourusername
```

You'll be prompted for your SSH key passphrase (if applicable).


## Verification with Trust Validation

When verifying signed manifests, ByteCheck performs two levels of verification:

1. **Integrity Verification** - Standard file checksum validation
2. **Trust Verification** - Cryptographic signature validation against trusted sources


### Trust Sources
ByteCheck supports multiple trust sources for public key validation:

#### GitHub-based Trust
```bash
# Verify against GitHub user's public keys
bytecheck verify /your/data

```

#### Custom Key Trust
```bash
# Use local public key files

bytecheck generate /your/data --private-key ~/.ssh/id_ed25519 --auditor-reference custom:yourusername
```

And verify:
```
export BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE="file:///some/directory/%s.pub"
bytecheck verify /your/data
```
