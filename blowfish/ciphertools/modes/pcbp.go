package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type PcbcMode struct {
}

func NewPcbcMode() *PcbcMode {
    return &PcbcMode{}
}

func (mode *PcbcMode) EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte {
    block2encrypt, _ := xorBytes(cipher.Buffer, plainText)
    cipherText := cipher.Encrypt(block2encrypt)
    iv, _ := xorBytes(cipherText, plainText)
    copy(cipher.Buffer, iv)

    return cipherText
}

func (mode *PcbcMode) DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte {
    plainText, _ := xorBytes(cipher.Decrypt(cipherText), cipher.Buffer)
    iv, _ := xorBytes(plainText, cipherText)
    copy(cipher.Buffer, iv)

    return plainText
}