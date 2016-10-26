package files

import (
    "bufio"
    "io"
    "os"
    "fmt"
    "time"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/options"
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

            transformedBlock := cipher.Decrypt(block)
            if _, err = writer.Write(transformedBlock[:8 - extraSymbolCount]); err != nil {
                return err
            }

            break
        }

        decryptedBlock := cipher.Decrypt(block)
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

func encryptBlock(cipher *ciphertools.Cipher, block []byte, mode string) []byte {
    switch mode {
    case options.MODE_ECB:
        // nothing
        break
    case options.MODE_CBC:
        break
    default:
        panic("An unknown mode was selected.")
    }

    encryptedBlock := cipher.Encrypt(block)
    return encryptedBlock
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