package main

import (
	"encoding/json"
	"reflect"
	"strings"
)

func Anonymize(s interface{}) ([]byte, error) {
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

		anonymize := val.Type().Field(i).Tag.Get("anonymize")
		if anonymize != "" {
			anonymizeParts := strings.SplitN(anonymize, ":", 2)
			if ruler, ok := rulerBuiltinLookup[anonymizeParts[0]]; ok {
				if len(anonymizeParts) > 1 {
					ruler.Replace(field, anonymizeParts[1])
				} else if len(anonymizeParts) == 1 {
					ruler.Replace(field, "")
				}
			}
		}
	}
	return json.Marshal(s)
}
