import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import AdmZip from 'adm-zip'

/**
 * The magic bytes that mark the start of a ZIP file inside an SU3 container.
 */
export const ZIP_MAGIC: Buffer = Buffer.from([0x50, 0x4b, 0x03, 0x04])

/** SU3 signature type → Node.js algorithm name */
const SIG_ALGORITHMS: Record<number, string> = {
	3: 'SHA256', // DSA-SHA1 (not used for reseed)
	4: 'SHA256', // ECDSA-SHA256-P256
	5: 'SHA384', // ECDSA-SHA384-P384
	6: 'SHA512', // RSA-SHA512-4096 (most common for reseed)
	8: 'SHA512', // EdDSA (not standard node crypto, but listed)
}

export interface Su3Header {
	sigType: number
	sigLength: number
	versionLength: number
	signerIdLength: number
	contentLength: number
	fileType: number
	contentType: number
	version: string
	signerId: string
}

/**
 * Parse the SU3 header from a raw buffer.
 * Returns null if the buffer doesn't start with the I2Psu3 magic.
 */
export function parseSu3Header(buf: Buffer): Su3Header | null {
	if (buf.length < 40) return null
	const magic = buf.subarray(0, 6).toString('ascii')
	if (magic !== 'I2Psu3') return null

	const sigType = buf.readUInt16BE(8)
	const sigLength = buf.readUInt16BE(10)
	const versionLength = buf[13] ?? 0
	const signerIdLength = buf[15] ?? 0

	// Content length is 8 bytes big-endian at offset 16
	// In practice it fits in 4 bytes (high 4 are 0)
	const contentLength =
		buf.readUInt32BE(16) * 0x100000000 + buf.readUInt32BE(20)

	const fileType = buf[25] ?? 0
	const contentType = buf[27] ?? 0

	const headerEnd = 40
	const version = buf
		.subarray(headerEnd, headerEnd + versionLength)
		.toString('ascii')
		.replace(/\0/g, '')
	const signerId = buf
		.subarray(
			headerEnd + versionLength,
			headerEnd + versionLength + signerIdLength,
		)
		.toString('ascii')

	return {
		sigType,
		sigLength,
		versionLength,
		signerIdLength,
		contentLength,
		fileType,
		contentType,
		version,
		signerId,
	}
}

/**
 * Maps a signer ID like "sahil@mail.i2p" to cert filename "sahil_at_mail.i2p.crt"
 */
export function signerIdToCertFile(signerId: string): string {
	return `${signerId.replace('@', '_at_')}.crt`
}

/**
 * Verify the cryptographic signature of an SU3 file against a PEM certificate.
 * Returns true if valid, false otherwise.
 */
export function verifySu3Signature(
	su3Buffer: Buffer,
	certPem: string,
): boolean {
	const header = parseSu3Header(su3Buffer)
	if (!header) return false

	const algo = SIG_ALGORITHMS[header.sigType]
	if (!algo) {
		console.error(`Unknown SU3 signature type: ${header.sigType}`)
		return false
	}

	// Signed data is everything before the signature
	const contentStart = 40 + header.versionLength + header.signerIdLength
	const signedDataEnd = contentStart + header.contentLength
	const signedData = su3Buffer.subarray(0, signedDataEnd)

	// Signature is at the end
	const signature = su3Buffer.subarray(
		signedDataEnd,
		signedDataEnd + header.sigLength,
	)

	try {
		const verifier = crypto.createVerify(algo)
		verifier.update(signedData)
		return verifier.verify(certPem, signature)
	} catch (err) {
		console.error('Signature verification error:', err)
		return false
	}
}

/**
 * Strips the SU3 header from a raw buffer and returns just the ZIP payload.
 * Returns `null` if no ZIP header is found.
 */
export function extractZipFromSu3(su3Buffer: Buffer): Buffer | null {
	const idx = su3Buffer.indexOf(ZIP_MAGIC)
	if (idx === -1) return null
	return su3Buffer.subarray(idx)
}

export interface ExtractResult {
	/** Total number of `.dat` entries written */
	count: number
	/** Base-names of the files that were written */
	files: string[]
}

/**
 * Extract all `routerInfo-*.dat` entries from every `.su3` file found in
 * `seedsDir` into `targetDir`. When `crtDir` and `servers` are provided,
 * verifies each SU3 against the cert mapped in reseed.json.
 * Returns the count and list of files written.
 */
export async function extractNetDb(
	seedsDir: string,
	targetDir: string,
	crtDir?: string,
	servers?: ReseedServer[],
): Promise<ExtractResult> {
	const dirEntries = await fs.readdir(seedsDir)
	const su3Files = dirEntries.filter((f) => f.endsWith('.su3'))

	if (su3Files.length === 0) {
		throw new Error('No seed .su3 files found in the seeds directory.')
	}

	await fs.mkdir(targetDir, { recursive: true })

	const written: string[] = []

	for (const su3File of su3Files) {
		const raw = await fs.readFile(path.join(seedsDir, su3File))

		// Verify against cert if crtDir + servers mapping is provided
		if (crtDir && servers) {
			const header = parseSu3Header(raw)
			if (!header) {
				console.error(`Skipping ${su3File}: invalid SU3 header`)
				continue
			}

			// Match hostname from filename against reseed.json URLs
			const hostname = su3File.replace(/\.su3$/, '')
			const server = servers.find((s) => {
				try {
					return new URL(s.url).hostname === hostname
				} catch {
					return false
				}
			})

			let certFileName: string
			if (server) {
				certFileName = server.crt_file
				// Ensure .crt extension
				if (!certFileName.endsWith('.crt')) {
					certFileName = `${certFileName}.crt`
				}
			} else {
				// Fallback: derive from signer ID in header
				certFileName = signerIdToCertFile(header.signerId)
			}

			let certPem: string
			try {
				certPem = await fs.readFile(path.join(crtDir, certFileName), 'utf8')
			} catch {
				console.error(`Skipping ${su3File}: cert not found (${certFileName})`)
				continue
			}

			const sigValid = verifySu3Signature(raw, certPem)
			if (sigValid) {
				console.log(`✓ ${su3File} verified (signer: ${header.signerId})`)
			} else {
				console.warn(
					`⚠ ${su3File}: signature mismatch (signer: ${header.signerId}) — cert may have rotated, proceeding`,
				)
			}
		}

		const zipPayload = extractZipFromSu3(raw)
		if (!zipPayload) {
			console.error(`Skipping ${su3File}: no ZIP payload found`)
			continue
		}

		const zip = new AdmZip(zipPayload)
		for (const entry of zip.getEntries()) {
			if (!entry.isDirectory && entry.entryName.endsWith('.dat')) {
				const name = path.basename(entry.entryName)
				// netDb uses subdirs like r0, rA, r~ based on first char of hash
				const hashStart = name.indexOf('-')
				const hashChar = hashStart !== -1 ? name[hashStart + 1] : undefined
				const subDir = hashChar ? `r${hashChar}` : 'r0'
				const fullDir = path.join(targetDir, subDir)
				await fs.mkdir(fullDir, { recursive: true })
				await fs.writeFile(path.join(fullDir, name), entry.getData())
				written.push(path.join(subDir, name))
			}
		}
	}

	return { count: written.length, files: written }
}

export interface ReseedServer {
	url: string
	crt_file: string
}

/**
 * Download fresh `.su3` files from reseed servers into `outputDir`.
 * Uses the built-in reseed.json list or a user-supplied one.
 */
export async function refreshSeeds(
	servers: ReseedServer[],
	outputDir: string,
	timeoutMs: number = 10000,
): Promise<string[]> {
	await fs.mkdir(outputDir, { recursive: true })

	const saved: string[] = []

	for (const { url } of servers) {
		try {
			const fullUrl = new URL('i2pseeds.su3', url).toString()
			console.log(`Downloading ${fullUrl}...`)
			const controller = new AbortController()
			const timeout = setTimeout(() => {
				controller.abort()
			}, timeoutMs)
			const response = await fetch(fullUrl, {
				headers: { 'User-Agent': 'Wget/1.21.2' },
				signal: controller.signal,
			})
			clearTimeout(timeout)
			if (!response.ok) {
				console.error(
					`Failed to download from ${fullUrl}: ${response.statusText}`,
				)
				continue
			}

			const buffer = Buffer.from(await response.arrayBuffer())
			const hostname = new URL(url).hostname
			const outFile = path.join(outputDir, `${hostname}.su3`)

			await fs.writeFile(outFile, buffer)
			saved.push(outFile)
			console.log(`Saved ${outFile}`)
		} catch (error) {
			console.error(`Error processing ${url}:`, error)
		}
	}

	return saved
}
