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
	Type  string `json:"type"`
	Value string `json:"value"`
	Field string `json:"field"`
}

func AnonymizeStruct(val reflect.Value, rules ...Rule) any {
	out := map[string]any{}
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		val = val.Elem()
	}
	switch val.Kind() {
	case reflect.Struct:
		for i := 0; i < val.Type().NumField(); i++ {
			currentValue := val.Field(i)
			field := val.Type().Field(i)
			tags := field.Tag
			outName := ""
			switch n := tags.Get("json"); n {
			case "":
				outName = field.Name
			case "-":
				outName = ""
			default:
				outName = n
			}
			if outName != "" {
				switch currentValue.Kind() {
				case reflect.Struct:
					out[outName] = AnonymizeStruct(currentValue, rules...)
					continue
				case reflect.Map:
					out[outName] = AnonymizeMap(currentValue)
					continue
				case reflect.Slice, reflect.Array:
					for i := 0; i < currentValue.Len(); i++ {
						out[outName] = AnonymizeStruct(currentValue.Index(i), rules...)
					}
					continue
				}
				var value any
				var foundRules bool
				for _, rule := range rules {
					if rule.Field == outName {
						if ruler, ok := rulerBuiltinLookup[rule.Type]; ok {
							foundRules = true
							value = ruler.Replace(currentValue, rule.Value)
						} else if ruler, ok := rulerCustomLookup[rule.Type]; ok {
							foundRules = true
							value = ruler.Replace(currentValue, rule.Value)
						}
					}
				}
				if !foundRules {
					tag := tags.Get("anonymize")
					if tag != "" {
						anonymizeParts := strings.SplitN(tag, ":", 2)
						if ruler, ok := rulerBuiltinLookup[anonymizeParts[0]]; ok {
							if len(anonymizeParts) > 1 {
								value = ruler.Replace(currentValue, anonymizeParts[1])
							} else if len(anonymizeParts) == 1 {
								value = ruler.Replace(currentValue, "")
							}
						} else if ruler, ok := rulerCustomLookup[anonymizeParts[0]]; ok {
							if len(anonymizeParts) > 1 {
								value = ruler.Replace(currentValue, anonymizeParts[1])
							} else if len(anonymizeParts) == 1 {
								value = ruler.Replace(currentValue, "")
							}
						}
					}
				}
				if value != nil {
					out[outName] = value
				} else {
					out[outName] = currentValue.Interface()
				}
			}
		}
	}
	return out
}

func AnonymizeMap(val reflect.Value, rules ...Rule) any {
	out := map[string]any{}
	switch val.Kind() {
	case reflect.Map:
		for _, field := range val.MapKeys() {
			fieldValue := val.MapIndex(field)
			var foundMap bool
			switch fieldValue.Kind() {
			case reflect.Interface:
				switch fieldValue.Elem().Kind() {
				case reflect.Map:
					switch v := fieldValue.Interface().(type) {
					case map[string]string, map[string]interface{}:
						foundMap = true
						out[field.String()] = AnonymizeMap(reflect.ValueOf(v), rules...)
					}
				case reflect.Struct:
					foundMap = true
					out[field.String()] = AnonymizeStruct(fieldValue, rules...)
				}
			}
			if !foundMap {
				var value any
				for _, rule := range rules {
					if rule.Field == field.String() {
						if ruler, ok := rulerBuiltinLookup[rule.Type]; ok {
							value = ruler.Replace(fieldValue, rule.Value)
						} else if ruler, ok := rulerCustomLookup[rule.Type]; ok {
							value = ruler.Replace(fieldValue, rule.Value)
						}
					}
				}
				if value != nil {
					out[field.String()] = value
				} else {
					out[field.String()] = fieldValue.Interface()
				}
			}
		}
	}
	return out
}

func Anonymize(src any, rules ...Rule) any {
	switch st := src.(type) {
	case []byte:
		return processBytes(st, rules...)
	case string:
		return processBytes(s2b(st), rules...)
	}
	source := reflect.ValueOf(src)
	switch source.Kind() {
	case reflect.Slice, reflect.Array:
		var responses []any
		for i := 0; i < source.Len(); i++ {
			val := source.Index(i)
			switch val.Kind() {
			case reflect.Struct:
				responses = append(responses, AnonymizeStruct(val, rules...))
			case reflect.Map:
				responses = append(responses, AnonymizeMap(val, rules...))
			}
		}
		return responses
	case reflect.Struct:
		return AnonymizeStruct(source, rules...)
	case reflect.Map:
		return AnonymizeMap(source, rules...)
	}
	return nil
}

func processBytes(data []byte, rules ...Rule) any {
	var src map[string]any
	var sources []map[string]any
	err := json.Unmarshal(data, &src)
	if err == nil {
		return AnonymizeMap(reflect.ValueOf(src), rules...)
	}
	err = json.Unmarshal(data, &sources)
	if err == nil {
		s := reflect.ValueOf(src)
		var responses []any
		for i := 0; i < s.Len(); i++ {
			val := s.Index(i)
			switch val.Kind() {
			case reflect.Struct:
				responses = append(responses, AnonymizeStruct(val, rules...))
			case reflect.Map:
				responses = append(responses, AnonymizeMap(val, rules...))
			}
		}
		return responses
	}
	return nil
}
