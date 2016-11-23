package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type EcbMode struct {
}

func NewEcbMode() *EcbMode {
    return &EcbMode{}
}

func (mode *EcbMode) EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte {
    return cipher.Encrypt(plainText)
}

func (mode *EcbMode) DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte {
    return cipher.Decrypt(cipherText)
}