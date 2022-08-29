package anonymizer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type Model struct {
	Anonymize bool `json:"anonymize"`
}

type Rule struct {
	Type  string
	Value string
	Param string
}

func Anonymize(s any, rules ...Rule) ([]byte, error) {
	switch reflect.ValueOf(s).Kind() {
	case reflect.Struct:
		anonymizeStruct("", reflect.ValueOf(s))
		return AnonymizeStruct(s, rules...)
	case reflect.Map:
		return AnonymizeMap(s, rules...)
	}
	return nil, nil
}

func Normal(s any, rules ...Rule) ([]byte, error) {
	switch reflect.ValueOf(s).Kind() {
	case reflect.Struct:
		return NormalStruct(s, rules...)
	case reflect.Map:
		return AnonymizeMap(s, rules...)
	}
	return nil, nil
}

func anonymizeStruct(tag string, v reflect.Value) {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			anonymizeStruct(tag, v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.Type().NumField(); i++ {
			tag := v.Type().Field(i).Tag.Get("anonymize")
			anonymizeStruct(tag, v.Field(i))
		}
	default:
		var value any

		if tag != "" {
			anonymizeParts := strings.SplitN(tag, ":", 2)
			if ruler, ok := RulerBuiltinLookup[anonymizeParts[0]]; ok {
				if len(anonymizeParts) > 1 {
					value = ruler.Replace(v, anonymizeParts[1])
				} else if len(anonymizeParts) == 1 {
					value = ruler.Replace(v, "")
				}
			}
		}
		if value != nil {
			v.Set(reflect.ValueOf(value))
		} else {
			v.Set(v)
		}
	}
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
			if ruler, ok := RulerBuiltinLookup[anonymizeParts[0]]; ok {
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

func AnonymizeMap(s any, rules ...Rule) ([]byte, error) {
	out := map[string]any{}
	if s == nil {
		return nil, nil
	}
	val := reflect.ValueOf(s)
	for _, k := range val.MapKeys() {
		field := val.MapIndex(k)
		switch reflect.ValueOf(field.Interface()).Kind() {
		case reflect.Map:
			mpData := map[string]any{}
			mapData, err := AnonymizeMap(field.Interface(), rules...)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(mapData, &mpData)
			if err != nil {
				return nil, err
			}
			out[k.String()] = mpData
		default:
			fmt.Println(k, field)
			var value any
			for _, rule := range rules {
				if rule.Param == k.String() {
					if ruler, ok := RulerBuiltinLookup[rule.Type]; ok {
						value = ruler.Replace(field, rule.Value)
					}
				}
				if value != nil {
					out[k.String()] = value
				} else {
					out[k.String()] = field.Interface()
				}
			}
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
				_, err := NormalStruct(field.Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		if fieldKind == reflect.Struct {
			if field.CanAddr() && field.Addr().CanInterface() {
				_, err := NormalStruct(field.Addr().Interface())
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
