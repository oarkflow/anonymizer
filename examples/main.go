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
}

func (u User) MarshalJSON() ([]byte, error) {
	if u.Anonymize {
		return anonymizer.Anonymize(u)
	}
	return anonymizer.Normal(u)
}

func main() {
	user := []User{
		{
			Model:      anonymizer.Model{Anonymize: true},
			ID:         1,
			FirstName:  "Sujit",
			Password:   "T#sT1234",
			Department: "IT Department",
		},
		{
			ID:         2,
			FirstName:  "Anita",
			Password:   "T#sT1234",
			Department: "Finance Department",
		},
	}
	u, err := json.Marshal(user)
	fmt.Println(string(u), err)
}
