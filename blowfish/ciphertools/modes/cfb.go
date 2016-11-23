package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type CfbMode struct {
}

func NewCfbMode() *CfbMode {
    return &CfbMode{}
}

func (mode *CfbMode) EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte {
    encIv := cipher.Encrypt(cipher.Buffer)

    cipherText, _ := xorBytes(encIv, plainText)
    copy(cipher.Buffer, cipherText)

    return cipherText
}

func (mode *CfbMode) DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte {
    encIv := cipher.Encrypt(cipher.Buffer)

    plainText, _ := xorBytes(encIv, cipherText)
    copy(cipher.Buffer, cipherText)

    return plainText
}