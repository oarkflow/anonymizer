package main

import (
	"anonymizer"
	"fmt"
	"reflect"
	"strings"
)

type User struct {
	anonymizer.Model
	ID         int    `json:"id" anonymize:"fake:{number:1}"`
	FirstName  string `json:"first_name" anonymize:"fake:{firstname}"`
	Password   string `json:"password" anonymize:"asterisk"`
	Department string `json:"department" anonymize:"encrypt:tN3XSDHWF8ZPOERtQRnkVMZYHgghteT7"`
	Address    Address
}

type Address struct {
	anonymizer.Model
	City    string `json:"city" anonymize:"fake:{city}"`
	Country string `json:"country" anonymize:"fake:{country}"`
}

var user = []User{
	{
		Model:      anonymizer.Model{Anonymize: true},
		ID:         1,
		FirstName:  "Sujit",
		Password:   "T#sT1234",
		Department: "IT Department",
		Address: Address{
			Model:   anonymizer.Model{Anonymize: true},
			City:    "Kathmandu",
			Country: "Nepal",
		},
	},
	{
		ID:         2,
		FirstName:  "Anita",
		Password:   "T#sT1234",
		Department: "Finance Department",
		Address: Address{
			Model:   anonymizer.Model{Anonymize: true},
			City:    "Pokhara",
			Country: "Nepal",
		},
	},
}

func structAnonymize() {
	fmt.Println(Anonymize(user))
}

func mapAnonymize() {
	rules := []anonymizer.Rule{
		{
			Type:  "fake",
			Value: "{firstname}",
			Param: "first_name",
		},
		{
			Type:  "fake",
			Value: "{city}",
			Param: "city",
		},
	}
	user := map[string]any{
		"id":         1,
		"first_name": "Sujit",
		"last_name":  "Baniya",
		"address": map[string]string{
			"city":    "Kathmandu",
			"country": "Nepal",
		},
	}
	fmt.Println(AnonymizeMap(reflect.ValueOf(user), rules...))
}

func main() {
	// structAnonymize()
	mapAnonymize()
}

func AnonymizeStruct(val reflect.Value) any {
	out := map[string]any{}
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		val = val.Elem()
	}
	switch val.Kind() {
	case reflect.Slice, reflect.Array:
		var responses []map[string]any
		for i := 0; i < val.Len(); i++ {
			o := AnonymizeStruct(val.Index(i))
			switch response := o.(type) {
			case map[string]any:
				responses = append(responses, response)
			}
		}
		return responses
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
					out[outName] = AnonymizeStruct(currentValue)
					continue
				case reflect.Slice, reflect.Array:
					for i := 0; i < currentValue.Len(); i++ {
						out[outName] = AnonymizeStruct(currentValue.Index(i))
					}
					continue
				}
				tag := tags.Get("anonymize")
				var value any
				if tag != "" {
					anonymizeParts := strings.SplitN(tag, ":", 2)
					if ruler, ok := anonymizer.RulerBuiltinLookup[anonymizeParts[0]]; ok {
						if len(anonymizeParts) > 1 {
							value = ruler.Replace(currentValue, anonymizeParts[1])
						} else if len(anonymizeParts) == 1 {
							value = ruler.Replace(currentValue, "")
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

func AnonymizeMap(val reflect.Value, rules ...anonymizer.Rule) map[string]any {
	out := map[string]any{}
	switch val.Kind() {
	case reflect.Map:
		for _, field := range val.MapKeys() {
			fieldValue := val.MapIndex(field)
			switch fieldValue.Kind() {
			case reflect.Interface:
				switch fieldValue.Elem().Kind() {
				case reflect.Map:
					switch v := fieldValue.Interface().(type) {
					case map[string]string, map[string]interface{}:
						out[field.String()] = AnonymizeMap(reflect.ValueOf(v), rules...)
					}
				default:
					var value any
					for _, rule := range rules {
						if rule.Param == field.String() {
							if ruler, ok := anonymizer.RulerBuiltinLookup[rule.Type]; ok {
								value = ruler.Replace(fieldValue, rule.Value)
							}
						}
						if value != nil {
							out[field.String()] = value
						} else {
							out[field.String()] = fieldValue.Interface()
						}
					}
				}
			default:
				var value any
				for _, rule := range rules {
					if rule.Param == field.String() {
						if ruler, ok := anonymizer.RulerBuiltinLookup[rule.Type]; ok {
							value = ruler.Replace(fieldValue, rule.Value)
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
	}
	return out
}

func Anonymize(src any) any {
	switch val := src.(type) {
	case reflect.Value:
		return AnonymizeStruct(val)
	default:
		return AnonymizeStruct(reflect.ValueOf(src))
	}
}
