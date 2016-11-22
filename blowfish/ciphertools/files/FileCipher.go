package files

import (
    "bufio"
    "io"
    "os"
    "fmt"
    "time"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/options"
    "encoding/binary"
)

func Decrypt(inputFile, outputFile *os.File, key []byte, mode string, debug bool) error {
    fmt.Printf("Decrypting file %v... \n", inputFile.Name())

    startTime := time.Now()

    cipher, createCipherErr := ciphertools.NewCipher(key)
    if createCipherErr != nil {
        return createCipherErr
    }

    afterExpandingKey := time.Now()

    fmt.Println("Decrypting...")

    reader := bufio.NewReader(inputFile)
    writer := bufio.NewWriter(outputFile)

    block := make([]byte, 8)

    for blockSize, err := reader.Read(block); blockSize != 0; blockSize, err = reader.Read(block) {
        if blockSize != 8 {
            fmt.Printf("Error. Data is damaged. Wrong block length. Block size: %v\n", blockSize)
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
                fmt.Printf("Service symbol is incorrect. %v\n", extraSymbolCount)
                return nil
            }

            transformedBlock := decryptBlock(cipher, block, mode)
            if _, err = writer.Write(transformedBlock[:8 - extraSymbolCount]); err != nil {
                return err
            }

            break
        }

        decryptedBlock := decryptBlock(cipher, block, mode)

        _, err = writer.Write(decryptedBlock)
        if err != nil {
            return err
        }
    }

    writer.Flush()

    fmt.Println("Decrypting successfully finished.")

    if debug {
        afterEncrypting := time.Now()
        fmt.Println("\nStatistic:")
        fmt.Printf("Time spent on blowfish algorithm: %v\n", afterExpandingKey.UnixNano() - startTime.UnixNano())
        fmt.Printf("Time spent on encrypting: %v\n", afterEncrypting.UnixNano() - afterExpandingKey.UnixNano())
        fmt.Printf("Time spent: %v\n", afterEncrypting.UnixNano() - startTime.UnixNano())
    }

    return nil
}

func xorBytes(a, b []byte) (dst []byte, n int) {
    n = len(a)
    dst = make([]byte, n)

    if len(b) < n {
        n = len(b)
    }

    for i := 0; i < n; i++ {
        dst[i] = a[i] ^ b[i]
    }

    return
}

func decryptBlock(cipher *ciphertools.Cipher, cipherText []byte, mode string) []byte {
    block2decrypt := cipherText

    switch mode {
    case options.MODE_ECB, options.MODE_CBC, options.MODE_PCBC:
        // nothing
        break
    case options.MODE_CFB, options.MODE_OFB, options.MODE_CTR:
        copy(block2decrypt, cipher.Buffer)
        break
    default:
        panic("An unknown mode was selected.")
    }

    plaintText := cipher.Decrypt(block2decrypt)

    switch mode {
    case options.MODE_ECB:
        // nothing
        break
    case options.MODE_CBC:
        plaintText, _ = xorBytes(cipher.Buffer, plaintText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_PCBC:
        plaintText, _ = xorBytes(plaintText, cipher.Buffer)
        cipher.Buffer, _ = xorBytes(plaintText, cipherText)
        break
    case options.MODE_CFB:
        plaintText, _ = xorBytes(plaintText, cipherText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_OFB:
        copy(cipher.Buffer, plaintText)
        plaintText, _ = xorBytes(plaintText, cipherText)
        break
    case options.MODE_CTR:
        counter := binary.BigEndian.Uint64(cipher.Buffer) + 1
        binary.BigEndian.PutUint64(cipher.Buffer, counter)

        plaintText, _ = xorBytes(plaintText, cipherText)
        break
    default:
        panic("An unknown mode was selected.")
    }

    return plaintText
}

func encryptBlock(cipher *ciphertools.Cipher, plaintText []byte, mode string) []byte {
    block2encrypt := plaintText

    switch mode {
    case options.MODE_ECB:
        // nothing
        break
    case options.MODE_CBC, options.MODE_PCBC:
        block2encrypt, _ = xorBytes(plaintText, cipher.Buffer)
        break
    case options.MODE_CFB, options.MODE_OFB, options.MODE_CTR:
        copy(block2encrypt, cipher.Buffer)
        break
    default:
        panic("An unknown mode was selected.")
    }

    cipherText := cipher.Encrypt(block2encrypt)

    switch mode {
    case options.MODE_ECB:
        // nothing
        break
    case options.MODE_CBC:
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_PCBC:
        cipher.Buffer, _ = xorBytes(cipherText, plaintText)
        break
    case options.MODE_CFB:
        cipherText, _ = xorBytes(cipherText, plaintText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_OFB:
        copy(cipher.Buffer, cipherText)
        cipherText, _ = xorBytes(cipherText, plaintText)
        break
    case options.MODE_CTR:
        counter := binary.BigEndian.Uint64(cipher.Buffer) + 1
        binary.BigEndian.PutUint64(cipher.Buffer, counter)

        cipherText, _ = xorBytes(cipherText, plaintText)
        break
    default:
        panic("An unknown mode was selected.")
    }

    return cipherText
}

func Encrypt(inputFile, outputFile *os.File, key []byte, mode string, debug bool) error {
    fmt.Printf("Encrypting file %v... \n", inputFile.Name())

    startTime := time.Now()

    cipher, createCipherErr := ciphertools.NewCipher(key)
    if createCipherErr != nil {
        return createCipherErr
    }

    afterExpandingKey := time.Now()

    fmt.Println("Encrypting..")

    reader := bufio.NewReader(inputFile)
    writer := bufio.NewWriter(outputFile)

    extraSymbolsCount := 0
    block := make([]byte, 8)

    for blockSize, err := reader.Read(block); blockSize != 0; blockSize, err = reader.Read(block) {
        if err != nil && err != io.EOF {
            return err
        }

        if blockSize < 8 {
            extraSymbolsCount = 8 - blockSize
            block = append(block, make([]byte, extraSymbolsCount)...)
        }

        encryptedBlock := encryptBlock(cipher, block, mode)
        _, err = writer.Write(encryptedBlock)
        if err != nil {
            return err
        }
    }

    writer.WriteByte(byte(extraSymbolsCount))

    writer.Flush()

    fmt.Println("Encrypting successfully finished.")

    if debug {
        afterEncrypting := time.Now()
        fmt.Println("\nStatistic:")
        fmt.Printf("Time spent on blowfish algorithm: %v\n", afterExpandingKey.UnixNano() - startTime.UnixNano())
        fmt.Printf("Time spent on encrypting: %v\n", afterEncrypting.UnixNano() - afterExpandingKey.UnixNano())
        fmt.Printf("Time spent: %v\n", afterEncrypting.UnixNano() - startTime.UnixNano())
    }

    return nil
}