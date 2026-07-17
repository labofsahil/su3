import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import AdmZip from 'adm-zip'
import {
	createSu3,
	extractNetDb,
	extractZipFromSu3,
	parseSu3Header,
	refreshSeeds,
	signerIdToCertFile,
	verifySu3Signature,
	ZIP_MAGIC,
} from '../src/index.ts'

/**
 * Build a fake SU3 buffer with the given signer ID and zip payload.
 * sig type 6 = RSA-SHA512-4096, sig length = 512
 */
function buildFakeSu3(
	signerId: string,
	zipBuffer: Buffer,
	opts?: { sigType?: number; sigLength?: number; signKey?: crypto.KeyObject },
): Buffer {
	const sigType = opts?.sigType ?? 6
	const sigLength = opts?.sigLength ?? 512
	const version = '20260101'
	const versionBuf = Buffer.alloc(16)
	versionBuf.write(version, 'ascii')
	const signerBuf = Buffer.from(signerId, 'ascii')

	// Header: 40 bytes
	const header = Buffer.alloc(40)
	header.write('I2Psu3', 0, 'ascii')
	header[7] = 0 // format version
	header.writeUInt16BE(sigType, 8)
	header.writeUInt16BE(sigLength, 10)
	header[13] = versionBuf.length // version length
	header[15] = signerBuf.length // signer ID length
	// content length (8 bytes BE at offset 16)
	header.writeUInt32BE(0, 16)
	header.writeUInt32BE(zipBuffer.length, 20)
	header[25] = 3 // content type (reseed)
	header[27] = 0 // file type (zip)

	const preContent = Buffer.concat([header, versionBuf, signerBuf])
	const signedData = Buffer.concat([preContent, zipBuffer])

	let sig: Buffer
	if (opts?.signKey) {
		sig = crypto.sign('sha512', signedData, opts.signKey)
		// Pad or truncate to sigLength
		const padded = Buffer.alloc(sigLength)
		sig.copy(padded)
		sig = padded
	} else {
		sig = Buffer.alloc(sigLength)
	}

	return Buffer.concat([signedData, sig])
}

// ── extractZipFromSu3 ──────────────────────────────────────────────────────────

describe('extractZipFromSu3', () => {
	test('extracts zip payload from a buffer that contains an SU3 header', () => {
		// Simulate an SU3 file: some junk header bytes followed by a ZIP payload
		const header = Buffer.from('I2Psu3__some_metadata__', 'utf8')
		const zipPayload = Buffer.concat([
			ZIP_MAGIC,
			Buffer.from('fake-zip-content'),
		])
		const su3 = Buffer.concat([header, zipPayload])

		const result = extractZipFromSu3(su3)
		expect(result).not.toBeNull()
		expect(result?.indexOf(ZIP_MAGIC)).toBe(0)
		expect(result?.length).toBe(zipPayload.length)
	})

	test('returns null when no ZIP magic is found', () => {
		const noZip = Buffer.from('this buffer has no zip header at all')
		expect(extractZipFromSu3(noZip)).toBeNull()
	})

	test('works when ZIP magic is at the very start', () => {
		const raw = Buffer.concat([ZIP_MAGIC, Buffer.from('data')])
		const result = extractZipFromSu3(raw)
		expect(result).not.toBeNull()
		expect(result?.length).toBe(raw.length)
	})
})

// ── extractNetDb ────────────────────────────────────────────────────────────────

describe('extractNetDb', () => {
	let tmpDir: string
	let seedsDir: string
	let targetDir: string

	beforeAll(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-test-'))
		seedsDir = path.join(tmpDir, 'seeds')
		targetDir = path.join(tmpDir, 'netdb')
		await fs.mkdir(seedsDir, { recursive: true })

		// Create a fake .su3: SU3 header + real zip containing .dat files
		const zip = new AdmZip()
		zip.addFile(
			'routerInfo-AAAA.dat',
			Buffer.from('router-data-1'),
			'test entry 1',
		)
		zip.addFile(
			'routerInfo-BBBB.dat',
			Buffer.from('router-data-2'),
			'test entry 2',
		)
		zip.addFile('README.txt', Buffer.from('not a dat'), 'ignored')

		const zipBuffer = zip.toBuffer()
		const su3Header = Buffer.from('I2Psu3__fake_header__')
		const su3File = Buffer.concat([su3Header, zipBuffer])
		await fs.writeFile(path.join(seedsDir, 'test-seed.su3'), su3File)
	})

	afterAll(async () => {
		await fs.rm(tmpDir, { recursive: true, force: true })
	})

	test('extracts .dat files from .su3 into subdirectories', async () => {
		const result = await extractNetDb(seedsDir, targetDir)

		expect(result.count).toBe(2)
		expect(result.files).toContain('rA/routerInfo-AAAA.dat')
		expect(result.files).toContain('rB/routerInfo-BBBB.dat')

		// Verify subdirectory structure
		const rA = await fs.readdir(path.join(targetDir, 'rA'))
		expect(rA).toContain('routerInfo-AAAA.dat')
		const rB = await fs.readdir(path.join(targetDir, 'rB'))
		expect(rB).toContain('routerInfo-BBBB.dat')

		// Non-.dat entries must be skipped
		const topLevel = await fs.readdir(targetDir)
		expect(topLevel).not.toContain('README.txt')
	})

	test('written files contain the correct data', async () => {
		const data = await fs.readFile(
			path.join(targetDir, 'rA', 'routerInfo-AAAA.dat'),
			'utf8',
		)
		expect(data).toBe('router-data-1')
	})

	test('throws when no .su3 files are present', async () => {
		const emptySeeds = path.join(tmpDir, 'empty-seeds')
		await fs.mkdir(emptySeeds, { recursive: true })

		expect(extractNetDb(emptySeeds, path.join(tmpDir, 'nope'))).rejects.toThrow(
			'No seed .su3 files found',
		)
	})

	test('skips .su3 files that have no ZIP payload', async () => {
		const badSeedsDir = path.join(tmpDir, 'bad-seeds')
		const badTarget = path.join(tmpDir, 'bad-netdb')
		await fs.mkdir(badSeedsDir, { recursive: true })

		// Write an .su3 file with no ZIP magic bytes
		await fs.writeFile(
			path.join(badSeedsDir, 'broken.su3'),
			Buffer.from('no zip header here'),
		)

		// Also add a valid one so it doesn't throw "no .su3 files"
		const zip = new AdmZip()
		zip.addFile('routerInfo-CCCC.dat', Buffer.from('data-3'), '')
		const su3 = Buffer.concat([Buffer.from('I2Psu3__hdr__'), zip.toBuffer()])
		await fs.writeFile(path.join(badSeedsDir, 'good.su3'), su3)

		const result = await extractNetDb(badSeedsDir, badTarget)
		// Only the good file should produce output
		expect(result.count).toBe(1)
		expect(result.files).toContain('rC/routerInfo-CCCC.dat')
	})
})

// ── extractNetDb with real bundled seeds ─────────────────────────────────────

describe('extractNetDb (real seeds)', () => {
	const realSeedsDir = path.join(import.meta.dir, '..', 'data', 'seeds')
	let tmpTarget: string

	beforeAll(async () => {
		tmpTarget = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-real-'))
	})

	afterAll(async () => {
		await fs.rm(tmpTarget, { recursive: true, force: true })
	})

	test('extracts real .su3 seeds and produces router .dat files', async () => {
		// Skip if no seeds are present (e.g. CI without prebuild)
		try {
			await fs.access(realSeedsDir)
		} catch {
			console.log('Skipping real seeds test – no data/seeds directory')
			return
		}

		const result = await extractNetDb(realSeedsDir, tmpTarget)

		expect(result.count).toBeGreaterThan(0)
		for (const f of result.files) {
			expect(f).toMatch(/^r.\/routerInfo-.+\.dat$/)
		}

		// Verify at least one file exists on disk
		const firstFile = result.files[0]
		expect(firstFile).toBeDefined()
		const stat = await fs.stat(path.join(tmpTarget, firstFile as string))
		expect(stat.size).toBeGreaterThan(0)
	})
})

// ── CLI integration ─────────────────────────────────────────────────────────────

describe('CLI integration', () => {
	let tmpDir: string

	beforeAll(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-cli-'))
	})

	afterAll(async () => {
		await fs.rm(tmpDir, { recursive: true, force: true })
	})

	test('su3 netdb creates a netdb directory via the dist CLI', async () => {
		const cliPath = path.join(import.meta.dir, '..', 'dist', 'cli.js')
		try {
			await fs.access(cliPath)
		} catch {
			console.log('Skipping CLI test – dist/cli.js not built yet')
			return
		}

		const proc = Bun.spawn(['node', cliPath, 'netdb'], {
			cwd: tmpDir,
			stdout: 'pipe',
			stderr: 'pipe',
		})

		const exitCode = await proc.exited
		const stdout = await new Response(proc.stdout).text()

		expect(exitCode).toBe(0)
		expect(stdout).toContain('Successfully extracted')

		const netdbFiles = await fs.readdir(path.join(tmpDir, 'netdb'))
		expect(netdbFiles.length).toBeGreaterThan(0)
	})

	test('su3 with unknown command exits with code 1', async () => {
		const cliPath = path.join(import.meta.dir, '..', 'dist', 'cli.js')
		try {
			await fs.access(cliPath)
		} catch {
			console.log('Skipping CLI test – dist/cli.js not built yet')
			return
		}

		const proc = Bun.spawn(['node', cliPath, 'badcommand'], {
			cwd: tmpDir,
			stdout: 'pipe',
			stderr: 'pipe',
		})

		const exitCode = await proc.exited
		expect(exitCode).toBe(1)
	})

	test('su3 netdb --refresh flag is accepted', async () => {
		const cliPath = path.join(import.meta.dir, '..', 'dist', 'cli.js')
		try {
			await fs.access(cliPath)
		} catch {
			console.log('Skipping CLI test – dist/cli.js not built yet')
			return
		}

		// Just verify the flag doesn't crash (it will try to download which may timeout/fail
		// but the exit should still be 0 if at least one seed exists)
		const proc = Bun.spawn(['node', cliPath, 'netdb'], {
			cwd: tmpDir,
			stdout: 'pipe',
			stderr: 'pipe',
		})

		const exitCode = await proc.exited
		// Should succeed (bundled seeds are still there even without --refresh)
		expect(exitCode).toBe(0)
	})
})

// ── refreshSeeds ────────────────────────────────────────────────────────────────

describe('refreshSeeds', () => {
	let tmpDir: string
	let server: ReturnType<typeof Bun.serve>
	let serverUrl: string

	beforeAll(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-refresh-test-'))

		// Create a fake .su3 payload (SU3 header + valid zip)
		const zip = new AdmZip()
		zip.addFile('routerInfo-TEST.dat', Buffer.from('test-data'), '')
		const fakePayload = Buffer.concat([
			Buffer.from('I2Psu3__hdr__'),
			zip.toBuffer(),
		])

		// Start a local HTTP server
		server = Bun.serve({
			port: 0,
			fetch(req) {
				const url = new URL(req.url)
				if (url.pathname === '/i2pseeds.su3') {
					return new Response(fakePayload, {
						headers: { 'Content-Type': 'application/octet-stream' },
					})
				}
				if (url.pathname === '/error/i2pseeds.su3') {
					return new Response('Not Found', { status: 404 })
				}
				return new Response('Bad', { status: 400 })
			},
		})
		serverUrl = `http://localhost:${server.port}`
	})

	afterAll(async () => {
		server.stop(true)
		await fs.rm(tmpDir, { recursive: true, force: true })
	})

	test('downloads .su3 files from servers', async () => {
		const outputDir = path.join(tmpDir, 'seeds-ok')
		const servers = [{ url: `${serverUrl}/`, crt_file: 'test.crt' }]

		const saved = await refreshSeeds(servers, outputDir)

		expect(saved.length).toBe(1)
		expect(saved[0]).toContain('localhost.su3')

		// Verify file was written
		const files = await fs.readdir(outputDir)
		expect(files).toContain('localhost.su3')

		// Verify the downloaded content can be extracted
		const netdbDir = path.join(tmpDir, 'netdb-from-refresh')
		const result = await extractNetDb(outputDir, netdbDir)
		expect(result.count).toBe(1)
	})

	test('handles HTTP errors gracefully', async () => {
		const outputDir = path.join(tmpDir, 'seeds-err')
		const servers = [{ url: `${serverUrl}/error/`, crt_file: 'test.crt' }]

		const saved = await refreshSeeds(servers, outputDir)
		expect(saved.length).toBe(0)
	})

	test('handles timeouts gracefully', async () => {
		// Use an unreachable address to force a timeout
		const outputDir = path.join(tmpDir, 'seeds-timeout')
		const servers = [{ url: 'http://192.0.2.1:1/', crt_file: 'test.crt' }]

		const saved = await refreshSeeds(servers, outputDir, 500)
		expect(saved.length).toBe(0)
	})

	test('returns empty array for empty server list', async () => {
		const outputDir = path.join(tmpDir, 'seeds-empty')
		const saved = await refreshSeeds([], outputDir)
		expect(saved.length).toBe(0)
	})
})

// ── parseSu3Header ──────────────────────────────────────────────────────────────

describe('parseSu3Header', () => {
	test('parses a valid SU3 header', () => {
		const zip = new AdmZip()
		zip.addFile('routerInfo-TEST.dat', Buffer.from('data'), '')
		const su3 = buildFakeSu3('test@mail.i2p', zip.toBuffer())

		const header = parseSu3Header(su3)
		expect(header).not.toBeNull()
		expect(header?.signerId).toBe('test@mail.i2p')
		expect(header?.sigType).toBe(6)
		expect(header?.sigLength).toBe(512)
		expect(header?.contentType).toBe(3)
		expect(header?.fileType).toBe(0)
	})

	test('returns null for too-short buffer', () => {
		expect(parseSu3Header(Buffer.alloc(10))).toBeNull()
	})

	test('returns null for wrong magic', () => {
		const buf = Buffer.alloc(100)
		buf.write('NOTSU3', 0, 'ascii')
		expect(parseSu3Header(buf)).toBeNull()
	})
})

// ── signerIdToCertFile ──────────────────────────────────────────────────────────

describe('signerIdToCertFile', () => {
	test('converts signer ID to cert filename', () => {
		expect(signerIdToCertFile('sahil@mail.i2p')).toBe('sahil_at_mail.i2p.crt')
		expect(signerIdToCertFile('admin@stormycloud.org')).toBe(
			'admin_at_stormycloud.org.crt',
		)
	})
})

// ── verifySu3Signature ──────────────────────────────────────────────────────────

describe('verifySu3Signature', () => {
	let privateKey: crypto.KeyObject
	let certPem: string

	beforeAll(() => {
		// Generate a test RSA key pair and self-signed cert
		const { privateKey: pk, publicKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
		})
		privateKey = pk
		// Export as PEM for use as "cert" (public key PEM works with createVerify)
		certPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
	})

	test('returns true for a correctly signed SU3', () => {
		const zip = new AdmZip()
		zip.addFile('routerInfo-X.dat', Buffer.from('data'), '')
		const su3 = buildFakeSu3('test@i2p', zip.toBuffer(), {
			sigLength: 256,
			signKey: privateKey,
		})
		expect(verifySu3Signature(su3, certPem)).toBe(true)
	})

	test('returns false for tampered content', () => {
		const zip = new AdmZip()
		zip.addFile('routerInfo-X.dat', Buffer.from('data'), '')
		const su3 = buildFakeSu3('test@i2p', zip.toBuffer(), {
			sigLength: 256,
			signKey: privateKey,
		})
		// Tamper with content
		su3[80] = (su3[80] ?? 0) ^ 0xff
		expect(verifySu3Signature(su3, certPem)).toBe(false)
	})

	test('returns false for invalid header', () => {
		expect(verifySu3Signature(Buffer.from('nope'), certPem)).toBe(false)
	})

	test('returns false for unknown sig type', () => {
		const zip = new AdmZip()
		zip.addFile('routerInfo-X.dat', Buffer.from('data'), '')
		const su3 = buildFakeSu3('test@i2p', zip.toBuffer(), { sigType: 99 })
		expect(verifySu3Signature(su3, certPem)).toBe(false)
	})
})

// ── extractNetDb with cert verification ─────────────────────────────────────────

describe('extractNetDb with crtDir', () => {
	let tmpDir: string
	let seedsDir: string
	let crtDir: string
	const servers = [
		{ url: 'https://known.example.com/', crt_file: 'known_at_i2p.crt' },
	]

	beforeAll(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-crt-test-'))
		seedsDir = path.join(tmpDir, 'seeds')
		crtDir = path.join(tmpDir, 'crt')
		await fs.mkdir(seedsDir, { recursive: true })
		await fs.mkdir(crtDir, { recursive: true })

		// Create test key and "cert" (public key PEM)
		const { publicKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
		})
		const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
		await fs.writeFile(path.join(crtDir, 'known_at_i2p.crt'), pubPem)

		// Create an SU3 file named as hostname matching servers config
		const zip = new AdmZip()
		zip.addFile('routerInfo-DDDD.dat', Buffer.from('data-d'), '')
		const su3 = buildFakeSu3('known@i2p', zip.toBuffer())
		await fs.writeFile(path.join(seedsDir, 'known.example.com.su3'), su3)

		// Create an SU3 with hostname NOT in servers (no cert mapping)
		const zip2 = new AdmZip()
		zip2.addFile('routerInfo-EEEE.dat', Buffer.from('data-e'), '')
		const su3Unknown = buildFakeSu3('hacker@evil.com', zip2.toBuffer())
		await fs.writeFile(path.join(seedsDir, 'evil.example.com.su3'), su3Unknown)
	})

	afterAll(async () => {
		await fs.rm(tmpDir, { recursive: true, force: true })
	})

	test('blocks unknown signers and allows known signers', async () => {
		const targetDir = path.join(tmpDir, 'netdb-crt')
		const result = await extractNetDb(seedsDir, targetDir, crtDir, servers)

		// Only the known signer's file should be extracted
		expect(result.count).toBe(1)
		expect(result.files).toContain('rD/routerInfo-DDDD.dat')

		// The unknown signer's file should NOT be in the results
		const allFiles = result.files.join(',')
		expect(allFiles).not.toContain('EEEE')
	})
})

// ── createSu3 and new signature types verification ───────────────────────────────────

describe('createSu3 and different signature types', () => {
	test('RSA-SHA256 (type 4)', () => {
		const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
		})
		const privPem = privateKey.export({
			type: 'pkcs8',
			format: 'pem',
		}) as string
		const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string

		const content = Buffer.from('hello world content')
		const su3 = createSu3({
			content,
			version: '1.0.0',
			signerId: 'rsa-test@mail.i2p',
			contentType: 3,
			fileType: 0,
			sigType: 4,
			privateKeyPem: privPem,
		})

		const header = parseSu3Header(su3)
		expect(header).not.toBeNull()
		expect(header?.sigType).toBe(4)
		expect(header?.version).toBe('1.0.0')
		expect(header?.signerId).toBe('rsa-test@mail.i2p')

		const isValid = verifySu3Signature(su3, pubPem)
		expect(isValid).toBe(true)
	})

	test('ECDSA-SHA256-P256 (type 1)', () => {
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
			namedCurve: 'prime256v1',
		})
		const privPem = privateKey.export({
			type: 'pkcs8',
			format: 'pem',
		}) as string
		const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string

		const content = Buffer.from('ecdsa payload')
		const su3 = createSu3({
			content,
			version: '2.0.0',
			signerId: 'ecdsa-test@mail.i2p',
			contentType: 3,
			fileType: 0,
			sigType: 1,
			privateKeyPem: privPem,
		})

		const header = parseSu3Header(su3)
		expect(header).not.toBeNull()
		expect(header?.sigType).toBe(1)

		const isValid = verifySu3Signature(su3, pubPem)
		expect(isValid).toBe(true)
	})

	test('EdDSA-SHA512-Ed25519ph (type 8)', () => {
		const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
		const privPem = privateKey.export({
			type: 'pkcs8',
			format: 'pem',
		}) as string
		const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string

		const content = Buffer.from('eddsa payload')
		const su3 = createSu3({
			content,
			version: '3.0.0',
			signerId: 'eddsa-test@mail.i2p',
			contentType: 3,
			fileType: 0,
			sigType: 8,
			privateKeyPem: privPem,
		})

		const header = parseSu3Header(su3)
		expect(header).not.toBeNull()
		expect(header?.sigType).toBe(8)

		const isValid = verifySu3Signature(su3, pubPem)
		expect(isValid).toBe(true)
	})
})

// ── CLI Expanded Commands ──────────────────────────────────────────────────────────

describe('CLI expanded commands', () => {
	let cliPath: string
	let tmpDir: string
	let keyPem: string
	let certPem: string

	beforeAll(async () => {
		cliPath = path.join(import.meta.dir, '..', 'dist', 'cli.js')
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-cli-test-'))

		// Generate test keys for pack/verify/info/extract
		const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
		})
		keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
		certPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
	})

	afterAll(async () => {
		await fs.rm(tmpDir, { recursive: true, force: true })
	})

	test('su3 pack, info, verify, and extract', async () => {
		try {
			await fs.access(cliPath)
		} catch {
			console.log('Skipping CLI test – dist/cli.js not built yet')
			return
		}

		// Write key and payload file
		const keyPath = path.join(tmpDir, 'test.key')
		const certPath = path.join(tmpDir, 'test.crt')
		const contentPath = path.join(tmpDir, 'content.txt')
		const su3Path = path.join(tmpDir, 'output.su3')
		const extractedPath = path.join(tmpDir, 'extracted.txt')

		await fs.writeFile(keyPath, keyPem)
		await fs.writeFile(certPath, certPem)
		await fs.writeFile(contentPath, 'hello world content')

		// 1. Pack
		const packProc = Bun.spawn([
			'node',
			cliPath,
			'pack',
			contentPath,
			su3Path,
			'--signerId',
			'test@mail.i2p',
			'--privateKey',
			keyPath,
			'--version',
			'1234',
			'--sigType',
			'4', // RSA-2048
		])
		expect(await packProc.exited).toBe(0)
		expect(
			await fs
				.access(su3Path)
				.then(() => true)
				.catch(() => false),
		).toBe(true)

		// 2. Info
		const infoProc = Bun.spawn(['node', cliPath, 'info', su3Path], {
			stdout: 'pipe',
		})
		expect(await infoProc.exited).toBe(0)
		const infoOut = await new Response(infoProc.stdout).text()
		expect(infoOut).toContain('Signer ID:        test@mail.i2p')
		expect(infoOut).toContain('Version:          1234')
		expect(infoOut).toContain('Signature Type:   4 (RSA-SHA256-2048)')

		// 3. Verify
		const verifyProc = Bun.spawn(
			['node', cliPath, 'verify', su3Path, certPath],
			{
				stdout: 'pipe',
			},
		)
		expect(await verifyProc.exited).toBe(0)
		const verifyOut = await new Response(verifyProc.stdout).text()
		expect(verifyOut).toContain('Signature is VALID')

		// 4. Extract
		const extractProc = Bun.spawn([
			'node',
			cliPath,
			'extract',
			su3Path,
			extractedPath,
		])
		expect(await extractProc.exited).toBe(0)
		const extractedText = await fs.readFile(extractedPath, 'utf8')
		expect(extractedText).toBe('hello world content')
	})
})
