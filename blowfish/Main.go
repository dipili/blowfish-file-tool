package main

import (
    "fmt"
    "flag"
    "io/ioutil"
    "os"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools/files"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/options"
)

var pars options.Options

func init() {
    flag.BoolVar(&pars.Encryption, "encrypt", false, "Should be set if you want to encrypt a specified file.")
    flag.BoolVar(&pars.Decryption, "decrypt", false, "Should be set if you want to decrypt a specified file.")
    flag.StringVar(&pars.InputFile, "input", "", "Input file.")
    flag.StringVar(&pars.OutputFile, "output", "", "Output file.")
    flag.StringVar(&pars.KeyFile, "key", "", "Key file.")
    flag.StringVar(&pars.Mode, "mode", options.MODE_ECB, "Block cipher mode of operation.")
}

func main() {
    fmt.Println("Starting blowfish cipher tool...")
    flag.Parse()

    if err := pars.Validate(); err != "" {
        fmt.Println(err)
        return
    }

    fmt.Printf("Program arguments: %v\n", pars)

    key, err := ioutil.ReadFile(pars.KeyFile)
    if err != nil {
        fmt.Printf("Error: %v", err)
        return
    }

    inputFile, err := os.Open(pars.InputFile)
    if err != nil {
        fmt.Printf("Error: %v", err)
        return
    }

    outputFile, err := os.Create(pars.OutputFile)
    if err != nil {
        fmt.Printf("Error: %v", err)
        return
    }

    var errOperation error
    if pars.Encryption {
        errOperation = files.Encrypt(inputFile, outputFile, key, pars.Mode)
    } else {
        errOperation = files.Decrypt(inputFile, outputFile, key, pars.Mode)
    }

    if errOperation != nil {
        fmt.Printf("Error: %v", errOperation)
        return
    }

    inputFile.Close()
    outputFile.Close()
}
