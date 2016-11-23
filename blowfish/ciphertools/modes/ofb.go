package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type OfbMode struct {
}

func NewOfbMode() *OfbMode {
    return &OfbMode{}
}

func (mode *OfbMode) EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte {
    encIv := cipher.Encrypt(cipher.Buffer)

    copy(cipher.Buffer, encIv)
    cipherText, _ := xorBytes(encIv, plainText)

    return cipherText
}

func (mode *OfbMode) DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte {
    encIv := cipher.Encrypt(cipher.Buffer)

    copy(cipher.Buffer, encIv)
    plainText, _ := xorBytes(encIv, cipherText)

    return plainText
}