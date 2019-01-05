package main

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/spacemeshos/go-bls"
	"log"
	"time"
)

// Playground

func signAndVerify() {

	sec1 := bls.NewSecretKey()

	// 32 bytes
	log.Printf("Priv key (32 bytes) GetLittleEndian(): 0x%x", sec1.GetLittleEndian())
	log.Printf("Priv key GetHexString() (bigEndian): 0x%s", sec1.GetHexString())
	log.Printf("Priv key getDecString(): %s", sec1.GetDecString())
	log.Printf("Priv key SerizlieToHexStr(): (littleEndian): 0x%s", sec1.SerializeToHexStr())


	// 96 bytes (eth is 64 bytes)
	pub1 := sec1.GetPublicKey()
	log.Printf("Pub key (96 bytes): 0x%x", pub1.Serialize())
	log.Printf("Pub key (96 bytes): 0x%s", pub1.SerializeToHexStr())

	m := []byte("super special message")
	sign1 := sec1.Sign(m)

	// 48 bytes (eth is 64-65 bytes long)
	log.Printf("Sig 1: (48 bytes) 0x%x", sign1.Serialize())

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

func hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum([]byte{})
}

func timeAggregation() {

	// this fails for larger values of n such as 500 or 1000
	const n = 255
	const hSize = 32 // sha256 creates 32 bytes hashes

	secs := make([]*bls.SecretKey, n)
	pubs := make([]bls.PublicKey, n)
	sigs := make([]*bls.Sign, n)
	hashes := make([][]byte, n)

	for i := 0; i < n; i++ {
		d := make([]byte, 256)
		_, err := rand.Read(d)
		if err != nil {
			panic("no entropy")
		}

		hashes[i] = hash(d)
		sec := bls.SecretKey{}
		sec.SetByCSPRNG()
		secs[i] = &sec
		pubs[i] = *sec.GetPublicKey()
		sigs[i] = sec.SignHash(hashes[i])
	}

	sig := sigs[0]
	for i := 1; i < n; i++ {
		sig.Add(sigs[i])
	}

	t := time.Now()

	if !sig.VerifyAggregatedHashes(pubs, hashes, hSize, n) {
		log.Fatal ("Verification failed")
	}

	e := time.Since(t)
	log.Printf("%d aggregated sigs verified in %s \n", n, e)

	hashes[0] = hash([]byte("a random message"))
	if sig.VerifyAggregatedHashes(pubs, hashes, hSize, n) {
		log.Fatal ("Expected verification to fail on tweaked data")
	}

	log.Println("Aggregate Signature Verifies Correctly!")
}

func main() {
	// timeAggregation()
	signAndVerify()
	// simpleAggregate()

}
