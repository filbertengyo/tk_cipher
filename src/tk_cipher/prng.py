"""PRNG TKRand, ARX 4x32-bit buatan sendiri untuk membangkitkan S-box dari key"""

MASK32 = 0xFFFFFFFF
G = 0x9E3779B9
WARMUP_ROUNDS = 32


def rotl(x: int, k: int) -> int:
    """Rotasi kiri word 32-bit.

    Args:
        x: Word 32-bit.
        k: Jumlah bit rotasi, 1 sampai 31.

    Returns:
        Hasil rotasi, tetap 32-bit.

    Example:
        >>> hex(rotl(0x80000001, 1))
        '0x3'
    """
    return ((x << k) | (x >> (32 - k))) & MASK32


def mix(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Satu putaran fungsi campur ARX atas empat word state.

    Args:
        a: Word state ke-0.
        b: Word state ke-1.
        c: Word state ke-2.
        d: Word state ke-3.

    Returns:
        Empat word state baru ``(a, b, c, d)``.

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
    """PRNG deterministik yang di-seed dari bytes.

    State awalnya ``[G, rotl(G, 8), rotl(G, 16), rotl(G, 24)]`` dengan
    ``G = 0x9E3779B9``. Tiap byte seed dijumlahkan ke ``s[i % 4]`` lalu state
    di-``mix``, diakhiri 32 kali ``mix`` sebagai warm-up. Seed yang sama selalu
    menghasilkan deret yang sama. Bukan pengganti CSPRNG.

    Args:
        seed: Bytes seed, panjang berapa pun (boleh kosong).

    Example:
        >>> a, b = TKRand(b"seed"), TKRand(b"seed")
        >>> a.next32() == b.next32()
        True
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
        """Ambil bilangan 32-bit berikutnya.

        Returns:
            Bilangan di ``[0, 2**32)``, yaitu ``s[0] ^ s[2]`` setelah ``mix``.

        Example:
            >>> 0 <= TKRand(b"x").next32() < 2**32
            True
        """
        self._s = mix(*self._s)
        return self._s[0] ^ self._s[2]

    def below(self, n: int) -> int:
        """Ambil bilangan seragam di ``[0, n)`` dengan rejection sampling.

        Nilai ``next32()`` di atas kelipatan ``n`` terbesar dibuang supaya
        tidak ada bias modulo.

        Args:
            n: Batas atas eksklusif, ``1 <= n <= 2**32``.

        Returns:
            Bilangan bulat di ``[0, n)``.

        Raises:
            ValueError: Kalau ``n`` di luar ``[1, 2**32]``.

        Example:
            >>> 0 <= TKRand(b"x").below(7) < 7
            True
        """
        if not 1 <= n <= 1 << 32:
            raise ValueError("n must be in [1, 2**32]")
        lim = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next32()
            if v < lim:
                return v % n
