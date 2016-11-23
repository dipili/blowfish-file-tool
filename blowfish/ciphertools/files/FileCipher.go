package files

import (
    "bufio"
    "io"
    "os"
    "time"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"
    "github.com/golang/glog"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools/modes"
    "crypto/rand"
)

func Encrypt(inputFile, outputFile *os.File, key []byte, mode modes.ICipherMode) error {
    glog.Infof("Encrypting file %v... \n", inputFile.Name())

    startTime := time.Now()

    cipher, createCipherErr := ciphertools.NewCipher(key)
    if createCipherErr != nil {
        return createCipherErr
    }

    afterExpandingKey := time.Now()

    glog.Infoln("Encrypting..")

    reader := bufio.NewReader(inputFile)
    writer := bufio.NewWriter(outputFile)

    extraSymbolsCount := 0
    block := make([]byte, 8)

    // write IV
    iv, _ := generateRandomBytes(8)
    copy(cipher.Buffer, iv)
    writer.Write(iv)

    for blockSize, err := reader.Read(block); blockSize != 0; blockSize, err = reader.Read(block) {
        if err != nil && err != io.EOF {
            return err
        }

        if blockSize < 8 {
            extraSymbolsCount = 8 - blockSize
            block = append(block, make([]byte, extraSymbolsCount)...)
        }

        encryptedBlock := mode.EncryptBlock(cipher, block)
        _, err = writer.Write(encryptedBlock)
        if err != nil {
            return err
        }
    }

    writer.WriteByte(byte(extraSymbolsCount))
    writer.Flush()

    glog.Infoln("Encrypting successfully finished.")

    afterEncrypting := time.Now()
    glog.Infof("Time spent on blowfish algorithm: %v\n", afterExpandingKey.UnixNano() - startTime.UnixNano())
    glog.Infof("Time spent on encrypting: %v\n", afterEncrypting.UnixNano() - afterExpandingKey.UnixNano())
    glog.Infof("Time spent: %v\n", afterEncrypting.UnixNano() - startTime.UnixNano())

    return nil
}

func Decrypt(inputFile, outputFile *os.File, key []byte, mode modes.ICipherMode) error {
    glog.Infof("Decrypting file %v... \n", inputFile.Name())

    startTime := time.Now()

    cipher, createCipherErr := ciphertools.NewCipher(key)
    if createCipherErr != nil {
        return createCipherErr
    }

    afterExpandingKey := time.Now()

    glog.Infoln("Decrypting...")

    reader := bufio.NewReader(inputFile)
    writer := bufio.NewWriter(outputFile)

    block := make([]byte, 8)

    // init IV
    reader.Read(block)
    copy(cipher.Buffer, block)

    for blockSize, err := reader.Read(block); blockSize != 0; blockSize, err = reader.Read(block) {
        if blockSize != 8 {
            glog.Errorf("Error. Data is damaged. Wrong block length. Block size: %v\n", blockSize)
            break
        }

        if err != nil && err != io.EOF {
            return err
        }

        _, errPeek := reader.Peek(2)
        if errPeek == io.EOF {
            lastByte, errorReadLastByte := reader.ReadByte()
            if (errorReadLastByte != nil) {
                panic("it's not ok")
            }

            extraSymbolCount := int(lastByte)
            if extraSymbolCount > 8 {
                glog.Infof("Service symbol is incorrect. %v\n", extraSymbolCount)
                return nil
            }

            transformedBlock := mode.DecryptBlock(cipher, block)
            if _, err = writer.Write(transformedBlock[:8 - extraSymbolCount]); err != nil {
                return err
            }

            break
        }

        decryptedBlock := mode.DecryptBlock(cipher, block)

        _, err = writer.Write(decryptedBlock)
        if err != nil {
            return err
        }
    }

    writer.Flush()

    glog.Infoln("Decrypting successfully finished.")

    afterEncrypting := time.Now()
    glog.Infof("Time spent on blowfish algorithm: %v\n", afterExpandingKey.UnixNano() - startTime.UnixNano())
    glog.Infof("Time spent on encrypting: %v\n", afterEncrypting.UnixNano() - afterExpandingKey.UnixNano())
    glog.Infof("Time spent: %v\n", afterEncrypting.UnixNano() - startTime.UnixNano())

    return nil
}

func generateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }

    return b, nil
}
