package main

import (
	"encoding/json"
	"fmt"
	"github.com/sujit-baniya/anonymizer"
)

type User struct {
	anonymizer.Model
	ID         int     `json:"id" anonymize:"fake:{number:1}"`
	FirstName  string  `json:"first_name" anonymize:"fake:{firstname}"`
	Password   string  `json:"password" anonymize:"asterisk"`
	Department string  `json:"department" anonymize:"encrypt:tN3XSDHWF8ZPOERtQRnkVMZYHgghteT7"`
	Avatar     string  `json:"avatar" anonymize:"fake:{imageurl:200,250}"`
	Address    Address `json:"address" anonymize:"encrypt:tN3XSDHWF8ZPOERtQRnkVMZYHgghteT7"`
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
		Avatar:     "test",
		Department: "IT Department",
		Address: Address{
			Model:   anonymizer.Model{Anonymize: true},
			City:    "Kathmandu",
			Country: "Nepal",
		},
	},
}

func structAnonymize() {
	rules := []anonymizer.Rule{
		{
			Type:  "asterisk",
			Value: "{firstname}",
			Param: "first_name",
		},
		{
			Type:  "fake",
			Value: "{city}",
			Param: "city",
		},
		{
			Type:  "fake",
			Value: "{country}",
			Param: "country",
		},
	}
	fmt.Println(anonymizer.Anonymize(user, rules...))
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
		{
			Type:  "fake",
			Value: "{country}",
			Param: "country",
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
	bt, _ := json.Marshal(user2)
	fmt.Println(anonymizer.Anonymize(bt, rules...))
}

func main() {
	structAnonymize()
	mapAnonymize()
}
