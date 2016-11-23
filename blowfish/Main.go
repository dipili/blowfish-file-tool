package main

import (
    "flag"
    "io/ioutil"
    "os"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/ciphertools/files"
    "github.com/diplombmstu/blowfish-file-tool/blowfish/options"
    "github.com/golang/glog"
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
    flag.Parse()
    glog.Infoln("Starting blowfish cipher tool...")

    if err := pars.Validate(); err != "" {
        glog.Errorln(err)
        return
    }

    glog.Infof("Program arguments: %v\n", pars)

    key, err := ioutil.ReadFile(pars.KeyFile)
    if err != nil {
        glog.Errorln(err.Error())
        return
    }

    inputFile, err := os.Open(pars.InputFile)
    if err != nil {
        glog.Infof("Error: %v", err)
        return
    }

    outputFile, err := os.Create(pars.OutputFile)
    if err != nil {
        glog.Infof("Error: %v", err)
        return
    }

    var errOperation error
    if pars.Encryption {
        errOperation = files.Encrypt(inputFile, outputFile, key, pars.Mode)
    } else {
        errOperation = files.Decrypt(inputFile, outputFile, key, pars.Mode)
    }

    if errOperation != nil {
        glog.Errorf("Error: %v", errOperation)
        return
    }

    inputFile.Close()
    outputFile.Close()
}
