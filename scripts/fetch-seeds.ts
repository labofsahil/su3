import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

interface ReseedUrl {
	url: string
	crt_file: string
}

const reseedPath = path.join(__dirname, '../src/reseed.json')
const outputPath = path.join(__dirname, '../data/seeds')

async function main() {
	await fs.mkdir(outputPath, { recursive: true })

	const reseedData: ReseedUrl[] = JSON.parse(
		await fs.readFile(reseedPath, 'utf8'),
	)

	for (const { url } of reseedData) {
		try {
			const fullUrl = new URL('i2pseeds.su3', url).toString()
			console.log(`Downloading ${fullUrl}...`)
			const controller = new AbortController()
			const timeout = setTimeout(() => {
				controller.abort()
			}, 10000)
			const response = await fetch(fullUrl, {
				headers: {
					'User-Agent': 'Wget/1.21.2',
				},
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
			const outFile = path.join(outputPath, `${hostname}.su3`)

			await fs.writeFile(outFile, buffer)
			console.log(`Saved seed to ${outFile}`)
		} catch (error) {
			console.error(`Error processing ${url}:`, error)
		}
	}
}

main().catch(console.error)
