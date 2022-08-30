package main

import (
	"anonymizer"
	"fmt"
)

type User struct {
	anonymizer.Model
	ID         int     `json:"id" anonymize:"fake:{number:1}"`
	FirstName  string  `json:"first_name" anonymize:"fake:{firstname}"`
	Password   string  `json:"password" anonymize:"asterisk"`
	Department string  `json:"department" anonymize:"encrypt:tN3XSDHWF8ZPOERtQRnkVMZYHgghteT7"`
	Address    Address `json:"address"`
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
}

func structAnonymize() {
	// fmt.Println(anonymizer.Anonymize(user))
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
	/*user1 := []map[string]any{
		{
			"id":         1,
			"first_name": "Sujit",
			"last_name":  "Baniya",
			"address": map[string]string{
				"city":    "Kathmandu",
				"country": "Nepal",
			},
		},
	}
	fmt.Println(anonymizer.Anonymize(user1, rules...))*/
	user2 := map[string]any{
		"id":         1,
		"first_name": "Sujit",
		"last_name":  "Baniya",
		"address": map[string]string{
			"city":    "Kathmandu",
			"country": "Nepal",
		},
	}

	fmt.Println(anonymizer.Anonymize(user2, rules...))
}

func main() {
	structAnonymize()
	mapAnonymize()
}
