# i2pseeds

[![npm version](https://img.shields.io/npm/v/i2pseeds)](https://www.npmjs.com/package/i2pseeds)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A TypeScript library and CLI for I2P network reseeding. Parse and verify [SU3](https://geti2p.net/spec/updates#su3-file-specification) files, extract router info into a netDb directory, and download fresh seeds from reseed servers — all with cryptographic signature verification.

## Features

- **SU3 parsing** — read headers, signer IDs, content types, and version info
- **Signature verification** — verify RSA / ECDSA / DSA signatures against bundled X.509 certificates
- **NetDb extraction** — unpack `routerInfo-*.dat` entries into the standard `netdb/r*/` directory layout
- **Live reseeding** — download `.su3` files from community reseed servers with configurable timeouts
- **Bundled seeds & certs** — ships with pre-fetched seeds and all current reseed server certificates
- **CLI + API** — use from the command line or import into your own TypeScript / JavaScript project

## Installation

```bash
# npm
npm install i2pseeds

# bun
bun add i2pseeds
```

## CLI Usage

The CLI exposes a single `netdb` command that extracts router info into a `./netdb` directory.

```bash
# Extract from bundled seeds (no network access needed)
npx i2pseeds netdb

# Download fresh seeds from reseed servers first, then extract
npx i2pseeds netdb --refresh
```

## Programmatic API

```ts
import {
  parseSu3Header,
  verifySu3Signature,
  extractZipFromSu3,
  extractNetDb,
  refreshSeeds,
} from "i2pseeds";
```

### `parseSu3Header(buf: Buffer): Su3Header | null`

Parse the SU3 header from a raw buffer. Returns `null` if the buffer does not start with the `I2Psu3` magic bytes.

```ts
const header = parseSu3Header(raw);
console.log(header?.signerId); // "sahil@mail.i2p"
console.log(header?.sigType); // 6 (RSA-SHA512-4096)
```

### `verifySu3Signature(su3Buffer: Buffer, certPem: string): boolean`

Verify the cryptographic signature of an SU3 file against a PEM-encoded certificate.

```ts
import fs from "node:fs/promises";

const cert = await fs.readFile("cert.crt", "utf8");
const valid = verifySu3Signature(su3Buffer, cert);
```

### `extractZipFromSu3(su3Buffer: Buffer): Buffer | null`

Strip the SU3 header and return the raw ZIP payload. Returns `null` if no ZIP magic is found.

### `extractNetDb(seedsDir, targetDir, crtDir?, servers?): Promise<ExtractResult>`

Extract all `routerInfo-*.dat` entries from every `.su3` file in `seedsDir` into `targetDir`. When `crtDir` and `servers` are provided, each file is verified against the mapped certificate.

```ts
const result = await extractNetDb("./seeds", "./netdb", "./certs", servers);
console.log(`Extracted ${result.count} router entries`);
```

### `refreshSeeds(servers, outputDir, timeoutMs?): Promise<string[]>`

Download fresh `.su3` files from the given reseed servers. Returns a list of saved file paths.

```ts
const saved = await refreshSeeds(servers, "./seeds", 15000);
```

## Reseed Servers

The package includes a [`reseed.json`](src/reseed.json) file mapping reseed server URLs to their certificate files. The bundled list currently covers 12 community reseed servers.

## CDN

The bundled reseed data and certificates can also be downloaded directly from jsDelivr:

```
https://cdn.jsdelivr.net/npm/i2pseeds@latest/dist/data/
```

## Development

```bash
# Install dependencies
bun install

# Build
bun run build

# Run tests
bun test

# Lint
bun run lint

# Type-check
bun run type-check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow.

## License

[MIT](LICENSE) © labofsahil