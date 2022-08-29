package anonymizer

import (
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
	Symbol string
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
		return field
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

var rulerBuiltinLookup map[string]Replacer
var rulerCustomLookup map[string]Replacer

func init() {
	rulerBuiltinLookup = make(map[string]Replacer)
	rulerCustomLookup = make(map[string]Replacer)
	rulerBuiltinLookup["fake"] = &Faker{}
	rulerBuiltinLookup["asterisk"] = &Asterisk{}
	rulerBuiltinLookup["empty"] = &Empty{}
}
