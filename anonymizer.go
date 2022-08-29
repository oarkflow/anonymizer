package anonymizer

import (
	"encoding/json"
	"reflect"
	"strings"
)

type Model struct {
	Anonymize bool `json:"anonymize"`
}

type Rule struct {
	Type  string
	Name  string
	Param string
}

func Anonymize(s any, rules ...Rule) ([]byte, error) {
	if reflect.ValueOf(s).Kind() == reflect.Struct {
		return AnonymizeStruct(s, rules...)
	}
	return nil, nil
}

func Normal(s any, rules ...Rule) ([]byte, error) {
	if reflect.ValueOf(s).Kind() == reflect.Struct {
		return NormalStruct(s, rules...)
	}
	return nil, nil
}

func AnonymizeStruct(s any, rules ...Rule) ([]byte, error) {
	out := map[string]any{}
	if s == nil {
		return nil, nil
	}
	val := reflect.ValueOf(s)
	t := reflect.TypeOf(s)
	if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		f := t.Field(i)
		fieldKind := field.Kind()
		if fieldKind == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			if field.CanInterface() {
				_, err := AnonymizeStruct(field.Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		if fieldKind == reflect.Struct {
			if field.CanAddr() && field.Addr().CanInterface() {
				_, err := AnonymizeStruct(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		outName := ""
		switch n := val.Type().Field(i).Tag.Get("json"); n {
		case "":
			outName = f.Name
		case "-":
			outName = ""
		default:
			outName = n
		}
		var value any
		anonymize := val.Type().Field(i).Tag.Get("anonymize")
		if anonymize != "" {
			anonymizeParts := strings.SplitN(anonymize, ":", 2)
			if ruler, ok := rulerBuiltinLookup[anonymizeParts[0]]; ok {
				if len(anonymizeParts) > 1 {
					value = ruler.Replace(field, anonymizeParts[1])
				} else if len(anonymizeParts) == 1 {
					value = ruler.Replace(field, "")
				}
			}
		}
		if value != nil {
			out[outName] = value
		} else {
			out[outName] = field.Interface()
		}
	}
	return json.Marshal(out)
}

func NormalStruct(s any, rules ...Rule) ([]byte, error) {
	out := map[string]any{}
	if s == nil {
		return nil, nil
	}
	val := reflect.ValueOf(s)
	t := reflect.TypeOf(s)
	if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		f := t.Field(i)
		fieldKind := field.Kind()
		if fieldKind == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			if field.CanInterface() {
				_, err := AnonymizeStruct(field.Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		if fieldKind == reflect.Struct {
			if field.CanAddr() && field.Addr().CanInterface() {
				_, err := AnonymizeStruct(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		outName := ""
		switch n := val.Type().Field(i).Tag.Get("json"); n {
		case "":
			outName = f.Name
		case "-":
			outName = ""
		default:
			outName = n
		}
		out[outName] = field.Interface()
	}
	return json.Marshal(out)
}