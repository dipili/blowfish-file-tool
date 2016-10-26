package ciphertools

import (
    "strconv"
    "fmt"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "blowfish/keytools: invalid key size " + strconv.Itoa(int(k))
}

func getNextWord(b []byte, pos *int) uint32 {
    var w uint32
    j := *pos
    for i := 0; i < 4; i++ {
        w = w<<8 | uint32(b[j])
        j++
        if j >= len(b) {
            j = 0
        }
    }
    *pos = j
    return w
}

func (c *Cipher) expandKey(key []byte) error {
    fmt.Println("Expanding key...")

    if k := len(key); k < 1 || k > 56 {
        return KeySizeError(k)
    }

    j := 0
    for i := 0; i < 18; i++ {
        c.p[i] ^= getNextWord(key, &j)
    }

    var left, right uint32
    for i := 0; i < 18; i += 2 {
        left, right = c.encryptBlock(left, right)
        c.p[i], c.p[i + 1] = left, right
    }

    for i := 0; i < 256; i += 2 {
        left, right = c.encryptBlock(left, right)
        c.s0[i], c.s0[i + 1] = left, right
    }
    for i := 0; i < 256; i += 2 {
        left, right = c.encryptBlock(left, right)
        c.s1[i], c.s1[i + 1] = left, right
    }
    for i := 0; i < 256; i += 2 {
        left, right = c.encryptBlock(left, right)
        c.s2[i], c.s2[i + 1] = left, right
    }
    for i := 0; i < 256; i += 2 {
        left, right = c.encryptBlock(left, right)
        c.s3[i], c.s3[i + 1] = left, right
    }

    return nil
}
