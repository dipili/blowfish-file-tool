package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"

type ICipherMode interface {
    EncryptBlock(cipher *ciphertools.Cipher, plainText []byte) []byte
    DecryptBlock(cipher *ciphertools.Cipher, cipherText []byte) []byte
}
