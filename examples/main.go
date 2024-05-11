package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/oarkflow/anonymizer"
)

func main() {
	pattern := `(?i)([^_]+)-([^_]+)_([^_]+)\.PDF`
	pattern2 := `(?i)<facility>-<enc_type>_<fin>\.PDF`
	re := regexp.MustCompile(pattern)
	// testLongString()
	// structAnonymize()
	// mapAnonymize()
	data := `test-PRO_12112.pdf`
	fmt.Println(re.FindAllStringSubmatch(data, -1))
	parse, err := anonymizer.Parse(data, pattern2)
	if err != nil {
		panic(err)
	}
	fmt.Println(parse)
}

func testLongString() {
	data := `
On 2024-01-01, omeone has made a commit on github on https://sujit-baniya:kjhkjhkjhkjhk@github.com/Orgware-Construct/clear20-frontend.git.
On further investigation, I found the user has email s.baniya.np@gmail.com and logged in with IP 142.250.194.206. His name ia John Doe and lives at 123 Main St, Anytown, CA 12345. Jane Smith can be reached at +9779856034616.

xoxp-123456789012-123456789012-123456789012-0123456789abcdef0123456789abcdef
`
	d := anonymizer.ParseMultiple(data)
	fmt.Println(d)
}

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
			Field: "first_name",
		},
		{
			Type:  "fake",
			Value: "{city}",
			Field: "city",
		},
		{
			Type:  "fake",
			Value: "{country}",
			Field: "country",
		},
	}
	fmt.Println(anonymizer.Anonymize(user, rules...))
}

func mapAnonymize() {
	rules := []anonymizer.Rule{
		{
			Type:  "fake",
			Value: "{firstname}",
			Field: "first_name",
		},
		{
			Type:  "fake",
			Value: "{city}",
			Field: "city",
		},
		{
			Type:  "fake",
			Value: "{country}",
			Field: "country",
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
