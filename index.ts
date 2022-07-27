import * as fs from 'fs'
import * as aesjs from 'aes-js'
import { unzipSync } from 'zlib'

const KEY = aesjs.utils.hex.toBytes('C53DB23870A1A2F71CAE64061FDD0E1157309DC85204D4C5BFDF25090DF2572C')
const IV = aesjs.utils.hex.toBytes('E915AA018FEF71FC508132E4BB4CEB42')
const BLOCK_SIZE = 65536

type TOC = {
    length: number
    entrySize: number
    numEntries: number
}

type Block = {
    name: string
    offset: number
    size: number
    fileOffset: number
}

type Version = {
    major: number,
    minor: number
}

class FileReader {
    buffer: Buffer
    index: number = 0

    constructor(buffer: Buffer) {
        this.buffer = buffer
    }

    public readString(length: number) {
        const str = this.buffer.slice(this.index, this.index + length).toString('utf-8')
        this.index += length
        return str
    }

    public readShort() {
        return this.readNumber(2)
    }

    public readInt() {
        return this.readNumber(4)
    }

    public readNumber(length: number) {
        if (this.index > this.buffer.length - length) throw 'eof'

        let number = 0
        for (let i = 0; i < length; i++) {
            number += this.buffer[this.index + i] * (256 ** (length - i - 1))
        }

        this.index += length

        return number
    }

    public skip(i: number) {
        this.index += i
    }
}

class PSARC extends FileReader {
    version: Version
    toc: TOC = {} as TOC
    blocks: Block[] = []
    blockSizes: number[] = []
    files: string[]

    constructor(buffer: Buffer) {
        super(buffer)
        this.readHeader()
        this.readTOC()

        const manifest = this.readBlock(this.blocks[0])
        this.files = manifest.toString('utf-8').split('\n')
    }

    public getManifest(): Buffer {
        const manifestFileIndex = this.files.findIndex(file => file.match(/^manifests\/.*.hsan$/)) + 1
        return this.readBlock(this.blocks[manifestFileIndex])
    }

    private readHeader() {
        if (this.readString(4) !== 'PSAR') throw 'magic does not equal PSAR'
        this.version = { major: this.readShort(), minor: this.readShort() }
        if (this.readString(4) !== 'zlib') throw 'compression type does not equal zlib'
        this.toc.length = this.readInt()
        this.toc.entrySize = this.readInt()
        this.toc.numEntries = this.readInt()
        if (this.readInt() !== BLOCK_SIZE) throw 'block size does not equal 65536'
        if (this.readInt() !== 4) throw 'archive flags do not equal 4'
    }

    private readTOC() {
        const tocEncryped = this.buffer.slice(this.index, this.index + this.toc.length - 32)
        const toc = this.decryptTOC(tocEncryped)

        const reader = new FileReader(toc)
        for (let i = 0; i < this.toc.numEntries; i++) {
            this.blocks.push({
                name: reader.readString(16),
                offset: reader.readInt(),
                size: reader.readNumber(5),
                fileOffset: reader.readNumber(5)
            })
        }

        try {
            while (true) {
                const val = reader.readShort()
                this.blockSizes.push(val === 0 ? BLOCK_SIZE : val)
            }
        } catch (error) {
            if (error !== 'eof') throw error
        }
    }

    private decryptTOC(toc: Buffer): Buffer {
        toc = this.addPadding(toc)

        const aes = new aesjs.ModeOfOperation.cfb(KEY, IV, 16)
        const res = aes.decrypt(toc)
        return Buffer.from(res.slice(0, this.toc.length))
    }

    private readBlock(block: Block): Buffer {
        let buffer = Buffer.alloc(0)

        let offset = block.fileOffset

        for (let i = block.offset; i < this.blockSizes.length; i++) {
            const section = this.buffer.slice(offset, offset + this.blockSizes[i])
            const sectionUnzipped = unzipSync(section)

            buffer = Buffer.concat([buffer, sectionUnzipped])

            if (buffer.length === block.size) break
            if (buffer.length > block.size) throw ''

            offset += this.blockSizes[i]
        }

        return buffer
    }

    private addPadding(buffer: Buffer): Buffer {
        if (buffer.length % 16 !== 0) {
            buffer = Buffer.concat([buffer], buffer.length + (16 - buffer.length % 16))
        }

        return buffer
    }
}

function main() {
    if (process.argv.length < 3) console.info('Usage: ts-node/node index.js [path_to_chart]')
    else {
        try {
            const file = fs.readFileSync(process.argv[2])
            const psarc = new PSARC(file)
            const manifest = psarc.getManifest()
            fs.writeFileSync('manifest.json', manifest.toString('utf-8'))
        } catch (error) {
            if (error.code === 'ENOENT') console.error('Error: File not found')
            else console.error(error)
        }
    }
}

main()
