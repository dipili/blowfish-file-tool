package ciphertools

type Cipher struct {
    p              [18]uint32
    s0, s1, s2, s3 [256]uint32

    Buffer         []byte
}

func (c *Cipher) initCipher() {
    copy(c.p[0:], p[0:])
    copy(c.s0[0:], s0[0:])
    copy(c.s1[0:], s1[0:])
    copy(c.s2[0:], s2[0:])
    copy(c.s3[0:], s3[0:])

    c.Buffer = make([]byte, 8)
}

func NewCipher(key []byte) (*Cipher, error) {
    var result Cipher
    if k := len(key); k < 1 || k > 56 {
        return nil, KeySizeError(k)
    }

    result.initCipher()
    result.expandKey(key)

    return &result, nil
}

func (c *Cipher) f(x uint32, p uint32) uint32 {
    return ((c.s0[byte(x >> 24)] + c.s1[byte(x >> 16)]) ^ c.s2[byte(x >> 8)]) + c.s3[byte(x)] ^ p
}

func (c Cipher) encryptBlock(left, right uint32) (uint32, uint32) {
    resultLeft, resultRight := left, right

    resultLeft ^= c.p[0]
    for i := 1; i < 17; i += 2 {
        resultRight ^= c.f(resultLeft, c.p[i])
        resultLeft ^= c.f(resultRight, c.p[i + 1])
    }
    resultRight ^= c.p[17]

    return resultRight, resultLeft
}

func (c Cipher) decryptBlock(left, right uint32) (uint32, uint32) {
    resultLeft, resultRight := left, right

    resultLeft ^= c.p[17]
    for i := 16; i >= 1; i -= 2 {
        resultRight ^= c.f(resultLeft, c.p[i])
        resultLeft ^= c.f(resultRight, c.p[i - 1])
    }
    resultRight ^= c.p[0]

    return resultRight, resultLeft
}

func slicesToArray(left, right uint32) []byte {
    result := make([]byte, 8)
    result[0], result[1], result[2], result[3] = byte(left >> 24), byte(left >> 16), byte(left >> 8), byte(left)
    result[4], result[5], result[6], result[7] = byte(right >> 24), byte(right >> 16), byte(right >> 8), byte(right)
    return result
}

func (c Cipher) Encrypt(block []byte) []byte {
    left := uint32(block[0]) << 24 | uint32(block[1]) << 16 | uint32(block[2]) << 8 | uint32(block[3])
    right := uint32(block[4]) << 24 | uint32(block[5]) << 16 | uint32(block[6]) << 8 | uint32(block[7])

    left, right = c.encryptBlock(left, right)

    return slicesToArray(c.encryptBlock(left, right))
}

func (c Cipher) Decrypt(block []byte) []byte {
    left := uint32(block[0]) << 24 | uint32(block[1]) << 16 | uint32(block[2]) << 8 | uint32(block[3])
    right := uint32(block[4]) << 24 | uint32(block[5]) << 16 | uint32(block[6]) << 8 | uint32(block[7])

    left, right = c.decryptBlock(left, right)

    return slicesToArray(c.decryptBlock(left, right))
}

