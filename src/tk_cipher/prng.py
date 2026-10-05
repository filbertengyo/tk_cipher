MASK32 = 0xFFFFFFFF
G = 0x9E3779B9
WARMUP_ROUNDS = 32


def rotl(x: int, k: int) -> int:
    """Rotasi kiri word 32-bit sebanyak k bit"""
    return ((x << k) | (x >> (32 - k))) & MASK32


def mix(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Satu putaran campur ARX (add-rotate-xor) atas empat word state"""
    a = (a + b) & MASK32
    d = rotl(d ^ a, 13)
    c = (c + d) & MASK32
    b = rotl(b ^ c, 9)
    a = (a + b) & MASK32
    d = rotl(d ^ a, 5)
    c = (c + d) & MASK32
    b = rotl(b ^ c, 11)
    return a, b, c, d


class TKRand:
    """PRNG ARX 4x32-bit deterministik, seed sama selalu menghasilkan deret sama
    Seed di-absorb per byte ke state lalu di-mix, ditutup 32 kali mix warm-up.
    """

    def __init__(self, seed: bytes) -> None:
        s = (G, rotl(G, 8), rotl(G, 16), rotl(G, 24))
        for i, byte in enumerate(seed):
            t = list(s)
            t[i % 4] = (t[i % 4] + byte) & MASK32
            s = mix(*t)
        for _ in range(WARMUP_ROUNDS):
            s = mix(*s)
        self._s = s

    def next32(self) -> int:
        """Ambil bilangan 32-bit berikutnya (s[0] ^ s[2] setelah mix)"""
        self._s = mix(*self._s)
        return self._s[0] ^ self._s[2]

    def below(self, n: int) -> int:
        """Ambil bilangan seragam di [0, n), rejection sampling tanpa bias modulo"""
        if not 1 <= n <= 1 << 32:
            raise ValueError("n must be in [1, 2**32]")
        lim = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next32()
            if v < lim:
                return v % n
