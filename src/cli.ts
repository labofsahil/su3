#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { ReseedServer } from './index.ts'
import { extractNetDb, refreshSeeds } from './index.ts'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

async function main() {
	const args = process.argv.slice(2)
	const command = args[0]

	if (command !== 'netdb') {
		console.error('Usage: su3 netdb [--refresh]')
		process.exit(1)
	}

	const doRefresh = args.includes('--refresh')
	const bundledSeedsDir = path.join(__dirname, 'data/seeds')
	const targetDir = path.join(process.cwd(), 'netdb')

	try {
		// Load reseed server list for cert matching and refresh
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
			// Use bundled .su3 files from the npm package release
			seedsDir = bundledSeedsDir
		}

		// Resolve cert directory for signature verification
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
