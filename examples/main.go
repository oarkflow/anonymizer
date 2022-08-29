package main

import (
	"anonymizer"
	"fmt"
)

type User struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name" anonymize:"fake:{firstname}"`
	Password  string `json:"password" anonymize:"asterisk"`
}

func main() {
	user := User{
		ID:        1,
		FirstName: "Sujit",
		Password:  "T#sT1234",
	}
	u, err := anonymizer.Anonymize(user)
	fmt.Println(string(u), err)
}
