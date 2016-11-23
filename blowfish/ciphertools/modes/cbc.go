package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type CbcMode struct {
}

func NewCbcMode() *CbcMode {
    return &CbcMode{}
}

func (mode *CbcMode) EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte {
    block2encrypt, _ := xorBytes(cipher.Buffer, plainText)
    cipherText := cipher.Encrypt(block2encrypt)
    copy(cipher.Buffer, cipherText)

    return cipherText
}

func (mode *CbcMode) DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte {
    plainText, _ := xorBytes(cipher.Buffer, cipher.Decrypt(cipherText))
    copy(cipher.Buffer, cipherText)

    return plainText
}