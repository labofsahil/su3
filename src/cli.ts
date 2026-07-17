#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import AdmZip from 'adm-zip'
import type { ReseedServer } from './index.ts'
import {
	createSu3,
	extractNetDb,
	parseSu3Header,
	refreshSeeds,
	SIG_TYPES,
	verifySu3Signature,
} from './index.ts'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function printHelp() {
	console.log(`
Usage:
  su3 netdb [--refresh]                            Fetch seeds and extract netdb router entries
  su3 info <file.su3>                              Print details of an SU3 file header
  su3 verify <file.su3> <cert.crt>                 Verify signature of an SU3 file
  su3 extract <file.su3> <outputFile>              Extract the raw payload from an SU3 file
  su3 pack <inputDirOrFile> <outFile.su3> [opts]   Package and sign content into an SU3 file

Options for pack:
  --signerId <id>       Signer identity (required, e.g., sahil@mail.i2p)
  --privateKey <file>   Path to the private key PEM file (required)
  --version <version>   Version string (default: current Unix epoch seconds)
  --contentType <type>  Content type ID (default: 3 for reseed)
  --fileType <type>     File type ID (default: 0 for zip, auto-detected otherwise)
  --sigType <type>      Signature type ID (default: 6 for RSA-SHA512-4096)
	`)
}

async function main() {
	const args = process.argv.slice(2)
	const command = args[0]

	if (!command || args.includes('--help') || args.includes('-h')) {
		printHelp()
		process.exit(0)
	}

	if (command === 'info') {
		const filePath = args[1]
		if (!filePath) {
			console.error('Error: file path is required.')
			printHelp()
			process.exit(1)
		}
		const buf = await fs.readFile(filePath)
		const header = parseSu3Header(buf)
		if (!header) {
			console.error('Invalid SU3 file: Magic header not found')
			process.exit(1)
		}
		const sigDetails = SIG_TYPES[header.sigType]
		console.log('SU3 Header Details:')
		console.log(`  Signer ID:        ${header.signerId}`)
		console.log(`  Version:          ${header.version}`)
		console.log(
			`  Signature Type:   ${header.sigType} (${sigDetails?.name ?? 'Unknown'})`,
		)
		console.log(`  Signature Length: ${header.sigLength} bytes`)
		console.log(`  Content Length:   ${header.contentLength} bytes`)
		console.log(`  Content Type:     ${header.contentType}`)
		console.log(`  File Type:        ${header.fileType}`)
		process.exit(0)
	}

	if (command === 'verify') {
		const filePath = args[1]
		const certPath = args[2]
		if (!filePath || !certPath) {
			console.error('Error: file path and cert path are required.')
			printHelp()
			process.exit(1)
		}
		const buf = await fs.readFile(filePath)
		const certPem = await fs.readFile(certPath, 'utf8')
		const isValid = verifySu3Signature(buf, certPem)
		if (isValid) {
			console.log('Signature is VALID')
			process.exit(0)
		} else {
			console.log('Signature is INVALID')
			process.exit(1)
		}
	}

	if (command === 'extract') {
		const filePath = args[1]
		const outPath = args[2]
		if (!filePath || !outPath) {
			console.error('Error: input file path and output file path are required.')
			printHelp()
			process.exit(1)
		}
		const buf = await fs.readFile(filePath)
		const header = parseSu3Header(buf)
		if (!header) {
			console.error('Invalid SU3 file: Magic header not found')
			process.exit(1)
		}
		const payloadStart = 40 + header.versionLength + header.signerIdLength
		const payload = buf.subarray(
			payloadStart,
			payloadStart + header.contentLength,
		)
		await fs.writeFile(outPath, payload)
		console.log(`Extracted raw payload (${payload.length} bytes) to ${outPath}`)
		process.exit(0)
	}

	if (command === 'pack') {
		const inputPath = args[1]
		const outputPath = args[2]
		if (!inputPath || !outputPath) {
			console.error('Error: input path and output path are required.')
			printHelp()
			process.exit(1)
		}

		const getOpt = (flag: string): string | undefined => {
			const idx = args.indexOf(flag)
			if (idx !== -1 && idx + 1 < args.length) {
				return args[idx + 1]
			}
			return undefined
		}

		const signerId = getOpt('--signerId')
		const privateKeyPath = getOpt('--privateKey')

		if (!signerId) {
			console.error('Error: --signerId is required.')
			process.exit(1)
		}
		if (!privateKeyPath) {
			console.error('Error: --privateKey path is required.')
			process.exit(1)
		}

		const version =
			getOpt('--version') ?? Math.floor(Date.now() / 1000).toString()
		const contentType = parseInt(getOpt('--contentType') ?? '3', 10)
		const fileTypeOpt = getOpt('--fileType')
		const sigType = parseInt(getOpt('--sigType') ?? '6', 10)

		let content: Buffer
		let fileType = fileTypeOpt !== undefined ? parseInt(fileTypeOpt, 10) : 0

		const stat = await fs.stat(inputPath)
		if (stat.isDirectory()) {
			console.log(`Zipping directory ${inputPath}...`)
			const zip = new AdmZip()
			zip.addLocalFolder(inputPath)
			content = zip.toBuffer()
			fileType = 0
		} else {
			content = await fs.readFile(inputPath)
			if (fileTypeOpt === undefined) {
				if (inputPath.endsWith('.zip')) {
					fileType = 0
				} else if (inputPath.endsWith('.xml')) {
					fileType = 1
				} else if (inputPath.endsWith('.xml.gz')) {
					fileType = 3
				} else {
					fileType = 0
				}
			}
		}

		const privateKeyPem = await fs.readFile(privateKeyPath, 'utf8')
		console.log(
			`Packaging & signing SU3 file (signer: ${signerId}, sigType: ${sigType})...`,
		)
		const su3Buf = createSu3({
			content,
			version,
			signerId,
			contentType,
			fileType,
			sigType,
			privateKeyPem,
		})

		await fs.writeFile(outputPath, su3Buf)
		console.log(`Successfully created signed SU3 file: ${outputPath}`)
		process.exit(0)
	}

	if (command !== 'netdb') {
		console.error(`Unknown command: ${command}`)
		printHelp()
		process.exit(1)
	}

	const doRefresh = args.includes('--refresh')
	const bundledSeedsDir = path.join(__dirname, 'data/seeds')
	const targetDir = path.join(process.cwd(), 'netdb')

	try {
		const reseedJsonPath = path.join(__dirname, 'data/reseed.json')
		let servers: ReseedServer[]
		try {
			servers = JSON.parse(await fs.readFile(reseedJsonPath, 'utf8'))
		} catch {
			const fallback = path.join(__dirname, '../src/reseed.json')
			servers = JSON.parse(await fs.readFile(fallback, 'utf8'))
		}

		let seedsDir: string

		if (doRefresh) {
			seedsDir = await fs.mkdtemp(path.join(os.tmpdir(), 'su3-refresh-'))
			console.log('Downloading fresh seeds from reseed servers...')
			const saved = await refreshSeeds(servers, seedsDir)
			if (saved.length === 0) {
				console.error(
					'Could not download any fresh seeds. Falling back to bundled seeds.',
				)
				seedsDir = bundledSeedsDir
			} else {
				console.log(`Downloaded ${saved.length} fresh .su3 files`)
			}
		} else {
			seedsDir = bundledSeedsDir
		}

		let crtDir: string
		try {
			crtDir = path.join(__dirname, 'crt')
			await fs.access(crtDir)
		} catch {
			crtDir = path.join(__dirname, '../src/crt')
		}

		const result = await extractNetDb(seedsDir, targetDir, crtDir, servers)
		console.log(
			`Successfully extracted ${result.count} router entries into ./netdb`,
		)
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
			console.error(
				'Could not find the seeds directory. Please make sure the package was installed correctly.',
			)
		} else {
			console.error('Error:', (error as Error).message)
		}
		process.exit(1)
	}
}

main().catch((error) => {
	console.error(error)
	process.exit(1)
})
