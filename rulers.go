package anonymizer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/brianvoe/gofakeit/v6"
	"hash/maphash"
	"math/rand"
	"reflect"
	"strings"
)

type Replacer interface {
	Replace(any, string) any
}

type Asterisk struct {
	Symbol string `json:"symbol"`
}

func (a *Asterisk) Replace(source any, name string) any {
	if a.Symbol == "" {
		a.Symbol = "*"
	}
	switch field := source.(type) {
	case reflect.Value:
		v := []rune(field.String())
		masked := make([]string, len(v))
		for idx := range masked {
			masked[idx] = "*"
		}
		m := strings.Join(masked, "")
		if field.CanSet() {
			field.Set(reflect.ValueOf(m))
		} else {
			return m
		}
		return field
	default:
		return source
	}
}

type Empty struct{}

func (a *Empty) Replace(source any, name string) any {
	switch field := source.(type) {
	case reflect.Value:
		if field.CanSet() {
			field.Set(reflect.ValueOf(""))
		}
		return ""
	default:
		return source
	}
}

type Hasher struct{}

func (a *Hasher) Replace(source any, name string) any {
	switch field := source.(type) {
	case reflect.Value:
		h := sha256.New()
		h.Write([]byte(field.String()))
		return hex.EncodeToString(h.Sum(nil))
	default:
		return source
	}
}

type Encrypter struct {
	Secret string `json:"secret"`
}

func (a *Encrypter) Replace(source any, name string) any {
	if name != "" {
		a.Secret = name
	}
	switch field := source.(type) {
	case reflect.Value:
		encrypted, _ := Encrypt(field.String(), a.Secret)
		return encrypted
	default:
		return source
	}
}

type Faker struct{}

var r = rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))

func (a *Faker) Replace(source any, name string) any {
	fName, fParams := parseNameAndParamsFromTag(name)
	if info := gofakeit.GetFuncLookup(fName); info != nil {
		mapParams := parseMapParams(info, fParams)
		fValue, err := info.Generate(r, mapParams, info)
		if err == nil {
			return fValue
		}
	}
	return source
}

func GetAllFakerFunctions() []reflect.Value {
	return reflect.ValueOf(gofakeit.FuncLookups).MapKeys()
}

func GetFakerKeyList() (keys []string) {
	keyValues := reflect.ValueOf(gofakeit.FuncLookups).MapKeys()
	for _, key := range keyValues {
		keys = append(keys, key.String())
	}
	return
}

var rulerBuiltinLookup = map[string]Replacer{
	"fake":     &Faker{},
	"asterisk": &Asterisk{},
	"empty":    &Empty{},
	"hash":     &Hasher{},
	"encrypt":  &Encrypter{},
}
var rulerCustomLookup = map[string]Replacer{}

func AddCustomReplacer(name string, replacer Replacer) error {
	if len(name) == 0 {
		return errors.New("replacer name is null")
	}
	if replacer == nil {
		return errors.New("replacer is nil")
	}
	rulerCustomLookup[name] = replacer
	return nil
}

func RemoveCustomReplacer(name string) error {
	if len(name) == 0 {
		return errors.New("replacer name is null")
	}
	if _, ok := rulerCustomLookup[name]; !ok {
		return errors.New("replacer is not exists")
	}
	return nil
}
