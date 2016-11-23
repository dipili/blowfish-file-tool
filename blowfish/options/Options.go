package options

import (
    "fmt"
    "flag"
)

const (
    MODE_ECB = "ecb"
    MODE_CBC = "cbc"
    MODE_PCBC = "pcbc"
    MODE_CFB = "cfb"
    MODE_OFB = "ofb"
    MODE_CTR = "ctr"
)

type Options struct {
    InputFile  string
    OutputFile string
    KeyFile    string
    Encryption bool
    Decryption bool
    Mode       string
}

type WrongArgumentsError string

func (f WrongArgumentsError) Error() string {
    return fmt.Sprintf("Wrong application arguments: %g", f)
}

func (options *Options) Validate() (err WrongArgumentsError) {
    fmt.Println("Parsing arguments...")
    if (!flag.Parsed()) {
        err = "Use flag.Parse first()"
        return
    }

    if options.Encryption == options.Decryption {
        err = "You must to specify encryption or decryption operation and only one."
        return
    }

    if options.InputFile == "" {
        err = "You must specify an input file."
        return
    }

    if options.KeyFile == "" {
        err = "You must specify a key file."
        return
    }

    if options.OutputFile == "" {
        options.OutputFile = options.OutputFile + "_output"
    }

    err = ""
    return
}
