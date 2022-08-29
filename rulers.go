package anonymizer

import (
	"crypto/sha256"
	"encoding/hex"
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

func (a *Faker) Replace(source any, name string) any {
	r := rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))
	switch field := source.(type) {
	case reflect.Value:
		fName, fParams := parseNameAndParamsFromTag(name)
		if info := gofakeit.GetFuncLookup(fName); info != nil {
			mapParams := parseMapParams(info, fParams)
			fValue, err := info.Generate(r, mapParams, info)
			if err != nil {
				return nil
			}
			if field.CanSet() {
				field.Set(reflect.ValueOf(fValue))
			} else {
				return fValue
			}
		}
		return field
	case string:
		fName, fParams := parseNameAndParamsFromTag(name)
		if info := gofakeit.GetFuncLookup(fName); info != nil {
			mapParams := parseMapParams(info, fParams)
			fValue, err := info.Generate(r, mapParams, info)
			if err != nil {
				return nil
			}
			return fValue
		}
		return field
	default:
		return source
	}
}

func GetAllFakerFunctions() []reflect.Value {
	return reflect.ValueOf(gofakeit.FuncLookups).MapKeys()
}

var rulerBuiltinLookup map[string]Replacer

func init() {
	rulerBuiltinLookup = make(map[string]Replacer)
	rulerBuiltinLookup["fake"] = &Faker{}
	rulerBuiltinLookup["asterisk"] = &Asterisk{}
	rulerBuiltinLookup["empty"] = &Empty{}
	rulerBuiltinLookup["hash"] = &Hasher{}
	rulerBuiltinLookup["encrypt"] = &Encrypter{}
}
