package anonymizer

import (
	"errors"
	"reflect"
)

func Pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	padded := make([]byte, bufLen+padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded, nil
}

func Unpad(padded []byte, size int) ([]byte, error) {
	if len(padded)%size != 0 {
		return nil, errors.New("pkcs7: Padded value wasn't in correct size.")
	}

	bufLen := len(padded) - int(padded[len(padded)-1])
	buf := make([]byte, bufLen)
	copy(buf, padded[:bufLen])
	return buf, nil
}

func RedactGithub(str string) string {
	pattern := "https://<username>:<token>@<domain>/<github>/<repo>"
	parse, err := Parse(str, pattern)
	if err != nil {
		return str
	}
	parsed := AnonymizeMap(reflect.ValueOf(parse), Rule{
		Type:  "asterisk",
		Field: "token",
	})
	if parsed == nil {
		return str
	}
	replace, err := Replace(parsed.(map[string]any), pattern)
	if err != nil {
		return str
	}
	return replace
}
