import Foundation

/// PAGE_SPEC §7 QR: ISO/IEC 18004, byte mode, ECC M, version 1–6 (smallest that fits), FIXED mask 0 — 1:1 port of the
/// Go reference `pades/internal/qr/qr.go` (identical matrix in every language).
enum QR {
    private struct Version {
        let ecPerBlock, blocks, dataPerBlock: Int
        let align: [Int]
    }

    private static let versions: [Version] = [
        Version(ecPerBlock: 0, blocks: 0, dataPerBlock: 0, align: []),
        Version(ecPerBlock: 10, blocks: 1, dataPerBlock: 16, align: []),
        Version(ecPerBlock: 16, blocks: 1, dataPerBlock: 28, align: [6, 18]),
        Version(ecPerBlock: 26, blocks: 1, dataPerBlock: 44, align: [6, 22]),
        Version(ecPerBlock: 18, blocks: 2, dataPerBlock: 32, align: [6, 26]),
        Version(ecPerBlock: 24, blocks: 2, dataPerBlock: 43, align: [6, 30]),
        Version(ecPerBlock: 16, blocks: 4, dataPerBlock: 27, align: [6, 34]),
    ]

    /// [row][col], true = dark. No quiet zone.
    static func encode(_ data: [UInt8]) throws -> [[Bool]] {
        guard let ver = (1...6).first(where: { 4 + 8 + 8 * data.count <= versions[$0].blocks * versions[$0].dataPerBlock * 8 }) else {
            throw DERError("QR data too long (≤ 106 bytes)")
        }
        let vi = versions[ver]
        let total = vi.blocks * vi.dataPerBlock
        var bits: [Bool] = []
        func put(_ v: Int, _ n: Int) { for i in stride(from: n - 1, through: 0, by: -1) { bits.append(v >> i & 1 == 1) } }
        put(0b0100, 4)
        put(data.count, 8)
        for b in data { put(Int(b), 8) }
        put(0, min(4, total * 8 - bits.count))
        while bits.count % 8 != 0 { bits.append(false) }
        var cw: [UInt8] = []
        for i in stride(from: 0, to: bits.count, by: 8) {
            var b: UInt8 = 0
            for j in 0..<8 where bits[i + j] { b |= 1 << (7 - j) }
            cw.append(b)
        }
        var i = 0
        while cw.count < total { cw.append(i % 2 == 0 ? 0xEC : 0x11); i += 1 }

        let gen = rsGenerator(vi.ecPerBlock)
        var dataBlocks: [[UInt8]] = [], ecBlocks: [[UInt8]] = []
        for b in 0..<vi.blocks {
            let d = Array(cw[(b * vi.dataPerBlock)..<((b + 1) * vi.dataPerBlock)])
            dataBlocks.append(d)
            ecBlocks.append(rsRemainder(d, gen))
        }
        var final: [UInt8] = []
        for i in 0..<vi.dataPerBlock { for b in 0..<vi.blocks { final.append(dataBlocks[b][i]) } }
        for i in 0..<vi.ecPerBlock { for b in 0..<vi.blocks { final.append(ecBlocks[b][i]) } }
        return place(ver, vi, final)
    }

    private static func place(_ ver: Int, _ vi: Version, _ final: [UInt8]) -> [[Bool]] {
        let n = 17 + 4 * ver
        var m = [[Bool]](repeating: [Bool](repeating: false, count: n), count: n)
        var fn = m
        func set(_ r: Int, _ c: Int, _ dark: Bool) { m[r][c] = dark; fn[r][c] = true }
        func finder(_ r0: Int, _ c0: Int) {
            for r in -1...7 {
                for c in -1...7 {
                    let rr = r0 + r, cc = c0 + c
                    if rr < 0 || cc < 0 || rr >= n || cc >= n { continue }
                    let dark = r >= 0 && r <= 6 && c >= 0 && c <= 6 &&
                        (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))
                    set(rr, cc, dark)
                }
            }
        }
        finder(0, 0)
        finder(0, n - 7)
        finder(n - 7, 0)
        if n - 8 > 8 {
            for i in 8..<(n - 8) {
                set(6, i, i % 2 == 0)
                set(i, 6, i % 2 == 0)
            }
        }
        for r in vi.align {
            for c in vi.align {
                if r < 9 && c < 9 || r < 9 && c > n - 9 || r > n - 9 && c < 9 { continue }
                for dr in -2...2 { for dc in -2...2 { set(r + dr, c + dc, max(abs(dr), abs(dc)) != 1) } }
            }
        }
        let f = formatBits(0b00 << 3 | 0)
        func fb(_ i: Int) -> Bool { f >> i & 1 == 1 }
        for i in 0...5 { set(i, 8, fb(i)) }
        set(7, 8, fb(6))
        set(8, 8, fb(7))
        set(8, 7, fb(8))
        for i in 9..<15 { set(8, 14 - i, fb(i)) }
        for i in 0..<8 { set(8, n - 1 - i, fb(i)) }
        for i in 8..<15 { set(n - 15 + i, 8, fb(i)) }
        set(n - 8, 8, true)

        var bit = 0
        var up = true
        var col = n - 1
        while col > 0 {
            if col == 6 { col -= 1 }
            for k in 0..<n {
                let r = up ? n - 1 - k : k
                for c in [col, col - 1] {
                    if fn[r][c] { continue }
                    var dark = false
                    if bit < final.count * 8 { dark = final[bit / 8] >> (7 - bit % 8) & 1 == 1 }
                    bit += 1
                    if (r + c) % 2 == 0 { dark.toggle() }
                    m[r][c] = dark
                }
            }
            up.toggle()
            col -= 2
        }
        return m
    }

    private static func formatBits(_ data: Int) -> Int {
        let g = 0x537
        var v = data << 10
        for i in stride(from: 14, through: 10, by: -1) where v >> i & 1 == 1 { v ^= g << (i - 10) }
        return (data << 10 | v) ^ 0x5412
    }

    // GF(256), primitive 0x11D.
    private static let gf: (exp: [UInt8], log: [UInt8]) = {
        var e = [UInt8](repeating: 0, count: 512), l = [UInt8](repeating: 0, count: 256)
        var x = 1
        for i in 0..<255 {
            e[i] = UInt8(x)
            l[x] = UInt8(i)
            x <<= 1
            if x & 0x100 != 0 { x ^= 0x11D }
        }
        for i in 255..<512 { e[i] = e[i - 255] }
        return (e, l)
    }()

    private static func mul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        if a == 0 || b == 0 { return 0 }
        return gf.exp[Int(gf.log[Int(a)]) + Int(gf.log[Int(b)])]
    }

    private static func rsGenerator(_ n: Int) -> [UInt8] {
        var g: [UInt8] = [1]
        for i in 0..<n {
            var next = [UInt8](repeating: 0, count: g.count + 1)
            for (j, c) in g.enumerated() {
                next[j] ^= c
                next[j + 1] ^= mul(c, gf.exp[i])
            }
            g = next
        }
        return Array(g.dropFirst())
    }

    private static func rsRemainder(_ data: [UInt8], _ gen: [UInt8]) -> [UInt8] {
        var rem = [UInt8](repeating: 0, count: gen.count)
        for d in data {
            let f = d ^ rem[0]
            rem.removeFirst()
            rem.append(0)
            for (i, g) in gen.enumerated() { rem[i] ^= mul(g, f) }
        }
        return rem
    }
}
