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
    "crypto/rand"
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

    // init IV
    if mode != options.MODE_ECB {
        reader.Read(block)
        copy(cipher.Buffer, block)
    }

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

    // write IV
    if mode != options.MODE_ECB {
        iv, _ := generateRandomBytes(8)
        copy(cipher.Buffer, iv)
        writer.Write(iv)
    }

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

func generateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }

    return b, nil
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
    block2decrypt := make([]byte, 8)

    switch mode {
    case options.MODE_ECB, options.MODE_CBC, options.MODE_PCBC:
        copy(block2decrypt, cipherText)
        break
    case options.MODE_CFB, options.MODE_OFB, options.MODE_CTR:
        copy(block2decrypt, cipher.Buffer)
        break
    default:
        panic("An unknown mode was selected.")
    }

    var plainText []byte
    if mode != options.MODE_CFB && mode != options.MODE_OFB {
        plainText = cipher.Decrypt(block2decrypt)
    } else {
        plainText = cipher.Encrypt(block2decrypt)
    }

    switch mode {
    case options.MODE_ECB:
        // nothing
        break
    case options.MODE_CBC:
        plainText, _ = xorBytes(cipher.Buffer, plainText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_PCBC:
        plainText, _ = xorBytes(plainText, cipher.Buffer)
        cipher.Buffer, _ = xorBytes(plainText, cipherText)
        break
    case options.MODE_CFB:
        plainText, _ = xorBytes(plainText, cipherText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_OFB:
        copy(cipher.Buffer, plainText)
        plainText, _ = xorBytes(plainText, cipherText)
        break
    case options.MODE_CTR:
        counter := binary.BigEndian.Uint64(cipher.Buffer) + 1
        binary.BigEndian.PutUint64(cipher.Buffer, counter)

        plainText, _ = xorBytes(plainText, cipherText)
        break
    default:
        panic("An unknown mode was selected.")
    }

    return plainText
}

func encryptBlock(cipher *ciphertools.Cipher, plainText []byte, mode string) []byte {
    block2encrypt := make([]byte, 8)

    switch mode {
    case options.MODE_ECB:
        copy(block2encrypt, plainText)
        break
    case options.MODE_CBC, options.MODE_PCBC:
        block2encrypt, _ = xorBytes(plainText, cipher.Buffer)
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
        cipher.Buffer, _ = xorBytes(cipherText, plainText)
        break
    case options.MODE_CFB:
        cipherText, _ = xorBytes(cipherText, plainText)
        copy(cipher.Buffer, cipherText)
        break
    case options.MODE_OFB:
        copy(cipher.Buffer, cipherText)
        cipherText, _ = xorBytes(cipherText, plainText)
        break
    case options.MODE_CTR:
        counter := binary.BigEndian.Uint64(cipher.Buffer) + 1
        binary.BigEndian.PutUint64(cipher.Buffer, counter)

        cipherText, _ = xorBytes(cipherText, plainText)
        break
    default:
        panic("An unknown mode was selected.")
    }

    return cipherText
}
