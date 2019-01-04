package main

import (
	"github.com/spacemeshos/go-bls"
	"log"
)

func signAndVerify() {
	var sec1 bls.SecretKey
	sec1.SetByCSPRNG()

	// 33 bytes (eth is 32 bytes)
	log.Printf("Private key: 0x%x", sec1.GetLittleEndian())

	// 96 bytes (eth is 64 bytes)
	pub1 := sec1.GetPublicKey()
	log.Printf("Pulic key: 0x%x", pub1.Serialize())

	m := []byte("super special message")
	sign1 := sec1.Sign(m)

	// 48 bytes (eth is 64-65 bytes long)
	log.Printf("Signature 1: 0x%x", sign1.Serialize())
	if !sign1.Verify(pub1, m) {
		log.Fatal("Aggregate Signature Does Not Verify")
	}
	log.Println("Aggregate Signature Verifies Correctly!")
}

// multiple signers - same message
func simpleAggregate() {
	var sec1 bls.SecretKey
	var sec2 bls.SecretKey
	sec1.SetByCSPRNG()
	sec2.SetByCSPRNG()

	pub1 := sec1.GetPublicKey()
	pub2 := sec2.GetPublicKey()

	m := []byte("super special message")
	sign1 := sec1.Sign(m)
	sign2 := sec2.Sign(m)

	log.Printf("Signature 1: 0x%x", sign1.Serialize())
	log.Printf("Signature 2: 0x%x", sign2.Serialize())
	sign1.Add(sign2)
	log.Printf("Signature 1 + 2 Aggregation: 0x%x", sign1.Serialize())
	pub1.Add(pub2)
	if !sign1.Verify(pub1, m) {
		log.Fatal("Aggregate Signature Does Not Verify")
	}
	log.Println("Aggregate Signature Verifies Correctly!")
}

func main() {
	signAndVerify()
	simpleAggregate()

}
