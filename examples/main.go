package main

import (
	"anonymizer"
	"encoding/json"
	"fmt"
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

func (u Address) MarshalJSON() ([]byte, error) {
	if u.Anonymize {
		return anonymizer.Anonymize(u)
	}
	return anonymizer.Normal(u)
}

func (u User) MarshalJSON() ([]byte, error) {
	if u.Anonymize {
		return anonymizer.Anonymize(u)
	}
	return anonymizer.Normal(u)
}

func structAnonymize() {
	user := []User{
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
	u, err := json.Marshal(user)
	fmt.Println(string(u), err)
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
		"address": map[string]any{
			"city":    "Kathmandu",
			"country": "Nepal",
		},
	}
	u, err := anonymizer.AnonymizeMap(user, rules...)
	fmt.Println(string(u), err)
}

func main() {
	structAnonymize()
	// mapAnonymize()
}
