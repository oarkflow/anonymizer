package main

import (
	"encoding/json"
	"os"
)

type User struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name" anonymize:"fake:{firstname}"`
	Password  string `json:"password" anonymize:"asterisk"`
}

func (u *User) MarshalJSON() ([]byte, error) {
	return Anonymize(u)
}

func main() {
	user := &User{
		ID:        1,
		FirstName: "Sujit",
		Password:  "T#sT1234",
	}
	e := json.NewEncoder(os.Stdout)
	e.Encode(user)
}
