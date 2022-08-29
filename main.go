package main

import (
	"encoding/json"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"hash/maphash"
	"math/rand"
	"reflect"
	"strings"
)

type Replacer interface {
	Replace(any, string, ...any) any
}

type Asterisk struct {
	Symbol string
}

func (a *Asterisk) Replace(source any, name string, params ...any) any {
	if a.Symbol == "" {
		a.Symbol = "*"
	}
	switch src := source.(type) {
	case string:
		v := []rune(src)
		masked := make([]string, len(v))
		for idx := range masked {
			masked[idx] = a.Symbol
		}
		return strings.Join(masked, "")
	default:
		return source
	}
}

type Empty struct{}

func (a *Empty) Replace(source any, name string, params ...any) any {
	return ""
}

type Faker struct{}

func (a *Faker) Replace(source any, name string, params ...any) any {
	return ""
}

type User struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name" anonymize:"fake:{firstname}"`
	Password  string `json:"password" anonymize:"asterisk"`
}

// Used for parsing the tag in a struct
func parseNameAndParamsFromTag(tag string) (string, string) {
	// Trim the curly on the beginning and end
	tag = strings.TrimLeft(tag, "{")
	tag = strings.TrimRight(tag, "}")
	// Check if has params separated by :
	fNameSplit := strings.SplitN(tag, ":", 2)
	fName := ""
	fParams := ""
	if len(fNameSplit) >= 1 {
		fName = fNameSplit[0]
	}
	if len(fNameSplit) >= 2 {
		fParams = fNameSplit[1]
	}
	return fName, fParams
}

func funcLookupSplit(str string) []string {
	out := []string{}
	for str != "" {
		if strings.HasPrefix(str, "[") {
			startIndex := strings.Index(str, "[")
			endIndex := strings.Index(str, "]")
			val := str[(startIndex) : endIndex+1]
			out = append(out, strings.TrimSpace(val))
			str = strings.Replace(str, val, "", 1)

			// Trim off comma if it has it
			if strings.HasPrefix(str, ",") {
				str = strings.Replace(str, ",", "", 1)
			}
		} else {
			strSplit := strings.SplitN(str, ",", 2)
			strSplitLen := len(strSplit)
			if strSplitLen >= 1 {
				out = append(out, strings.TrimSpace(strSplit[0]))
			}
			if strSplitLen >= 2 {
				str = strSplit[1]
			} else {
				str = ""
			}
		}
	}

	return out
}

// Used for parsing map params
func parseMapParams(info *gofakeit.Info, fParams string) *gofakeit.MapParams {
	// Get parameters, make sure params and the split both have values
	mapParams := gofakeit.NewMapParams()
	paramsLen := len(info.Params)

	// If just one param and its a string simply just pass it
	if paramsLen == 1 && info.Params[0].Type == "string" {
		mapParams.Add(info.Params[0].Field, fParams)
	} else if paramsLen > 0 && fParams != "" {
		splitVals := funcLookupSplit(fParams)
		mapParams = addSplitValsToMapParams(splitVals, info, mapParams)
	}
	if mapParams.Size() > 0 {
		return mapParams
	} else {
		return nil
	}
}

// Used for splitting the values
func addSplitValsToMapParams(splitVals []string, info *gofakeit.Info, mapParams *gofakeit.MapParams) *gofakeit.MapParams {
	for ii := 0; ii < len(splitVals); ii++ {
		if len(info.Params)-1 >= ii {
			if strings.HasPrefix(splitVals[ii], "[") {
				lookupSplits := funcLookupSplit(strings.TrimRight(strings.TrimLeft(splitVals[ii], "["), "]"))
				for _, v := range lookupSplits {
					mapParams.Add(info.Params[ii].Field, v)
				}
			} else {
				mapParams.Add(info.Params[ii].Field, splitVals[ii])
			}
		}
	}
	return mapParams
}

func Sanitize(s interface{}) ([]byte, error) {
	r := rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))
	if s == nil {
		return nil, nil
	}
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}
	valNumFields := val.NumField()
	for i := 0; i < valNumFields; i++ {
		field := val.Field(i)
		fieldKind := field.Kind()
		if fieldKind == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			if field.CanInterface() {
				_, err := Sanitize(field.Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		if fieldKind == reflect.Struct {
			if field.CanAddr() && field.Addr().CanInterface() {
				_, err := Sanitize(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}

		anonymize := val.Type().Field(i).Tag.Get("anonymize")
		if anonymize != "" {
			anonymizeParts := strings.SplitN(anonymize, ":", 2)
			if len(anonymizeParts) > 1 {
				switch anonymizeParts[0] {
				case "fake":
					fName, fParams := parseNameAndParamsFromTag(anonymizeParts[1])
					if info := gofakeit.GetFuncLookup(fName); info != nil {
						mapParams := parseMapParams(info, fParams)
						fValue, err := info.Generate(r, mapParams, info)
						if err != nil {
							return nil, err
						}
						if field.CanSet() {
							field.Set(reflect.ValueOf(fValue))
						}
					}
					break
				}
			} else if len(anonymizeParts) == 1 {
				switch anonymizeParts[0] {
				case "asterisk":
					v := []rune(field.String())
					masked := make([]string, len(v))
					for idx := range masked {
						masked[idx] = "*"
					}
					m := strings.Join(masked, "")
					if field.CanSet() {
						field.Set(reflect.ValueOf(m))
					}
					break
				case "empty":
					if field.CanSet() {
						field.Set(reflect.ValueOf(""))
					}
					break
				}
			}
		}
	}
	return json.Marshal(s)
}

func main() {
	user := User{
		ID:        1,
		FirstName: "Sujit",
		Password:  "T#sT1234",
	}
	bt, _ := Sanitize(user)
	fmt.Println(string(bt))
}
