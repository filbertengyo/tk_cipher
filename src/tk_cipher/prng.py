"""PRNG TKRand buatan sendiri (ARX 4x32-bit) buat shuffle S-box, bukan modul random"""

MASK32 = 0xFFFFFFFF
G = 0x9E3779B9
WARMUP_ROUNDS = 32


def rotl(x: int, k: int) -> int:
    """Rotasi kiri word 32-bit sebanyak k bit

    Args:
        x (int): word 32-bit
        k (int): jumlah bit rotasi, 1 sampai 31

    Returns:
        int: hasil rotasi, tetap 32-bit

    Raises:
        Tidak ada

    Example:
        >>> hex(rotl(0x80000000, 1))
        '0x1'
    """
    return ((x << k) | (x >> (32 - k))) & MASK32


def mix(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Satu putaran campur ARX (add, rotate, xor) atas empat word state

    Urutannya `a+=b; d=rotl(d^a,13); c+=d; b=rotl(b^c,9)` lalu diulang dengan
    rotasi 5 dan 11

    Args:
        a (int): word state ke 0
        b (int): word state ke 1
        c (int): word state ke 2
        d (int): word state ke 3

    Returns:
        tuple[int, int, int, int]: empat word state baru

    Raises:
        Tidak ada

    Example:
        >>> mix(0, 0, 0, 0)
        (0, 0, 0, 0)
    """
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

    State awal `[G, rotl(G,8), rotl(G,16), rotl(G,24)]` dengan `G = 0x9E3779B9`
    Seed di-absorb per byte ke state lalu di-mix, ditutup 32 kali mix warm-up

    Args:
        seed (bytes): seed bebas panjang, S-box pakai `b"TKC-SBOX" + key + len(key)`

    Example:
        >>> TKRand(b"seed").next32() == TKRand(b"seed").next32()
        True

    Note:
        Bukan CSPRNG. Cuma dipakai buat bikin S-box yang deterministik per key,
        IV tetap pakai `os.urandom`
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
        """Ambil bilangan 32-bit berikutnya (`s[0] ^ s[2]` setelah mix)

        Returns:
            int: bilangan 0 sampai 2**32 - 1

        Raises:
            Tidak ada

        Example:
            >>> 0 <= TKRand(b"x").next32() < 2**32
            True
        """
        self._s = mix(*self._s)
        return self._s[0] ^ self._s[2]

    def below(self, n: int) -> int:
        """Ambil bilangan seragam di [0, n) pakai rejection sampling tanpa bias modulo

        Args:
            n (int): batas atas eksklusif, 1 sampai 2**32

        Returns:
            int: bilangan 0 sampai n - 1

        Raises:
            ValueError: `n` di luar 1 sampai 2**32

        Example:
            >>> 0 <= TKRand(b"x").below(10) < 10
            True
        """
        if not 1 <= n <= 1 << 32:
            raise ValueError("n must be in [1, 2**32]")
        lim = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next32()
            if v < lim:
                return v % n
