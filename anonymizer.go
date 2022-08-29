package anonymizer

import (
	"encoding/json"
	"reflect"
	"strings"
)

func Anonymize(s interface{}) ([]byte, error) {
	out := map[string]interface{}{}
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
				_, err := Anonymize(field.Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		if fieldKind == reflect.Struct {
			if field.CanAddr() && field.Addr().CanInterface() {
				_, err := Anonymize(field.Addr().Interface())
				if err != nil {
					return nil, err
				}
			}
			continue
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
			out[f.Name] = value
		} else {
			out[f.Name] = field.Interface()
		}
	}
	return json.Marshal(out)
}
