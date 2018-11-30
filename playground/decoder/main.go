package main

import (
	"crypto/sha1"
	"encoding/base64"
	"io/ioutil"
	"log"
)

func main() {
	// Load The Base64 File
	Base64Cert, _ := ioutil.ReadFile("playground/cert.b64")
	log.Println(string(Base64Cert))

	// Decode It
	data, err := base64.StdEncoding.DecodeString(string(Base64Cert))
	if err != nil {
		log.Fatal("error:", err)
	}

	log.Println(data)

	// Save To File
	ioutil.WriteFile("playground/cert.der", data, 0644)

	// Determain The Fingureprint
	h := sha1.New()
	h.Write(data)
	log.Printf("% x", h.Sum(nil))
}
