package modes

import "github.com/diplombmstu/blowfish-file-tool/blowfish/options"

func rotateSliceLeft(slice []interface{}, p int) {
    sliceLen := len(slice)
    for i := p - 1; i < sliceLen; i++ {
        slice[i - p] = slice[i]
    }
}

func rotateSliceRight(slice []interface{}, p int) {
    sliceLen := len(slice)
    for i := sliceLen - p; i < sliceLen; i-- {
        slice[i + p] = slice[i]
    }
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

func CreateMode(modeName string) ICipherMode {
    switch modeName {
    case options.MODE_ECB:
        return NewEcbMode()
        break
    case options.MODE_CBC:
        return NewCbcMode()
        break
    case options.MODE_PCBC:
        return NewPcbcMode()
        break
    case options.MODE_CFB:
        return NewCfbMode()
        break
    case options.MODE_OFB:
        return NewOfbMode()
        break
    }

    panic("Impossible argument")
}