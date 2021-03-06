package bls

/*
#cgo CFLAGS:-I external/bls/include/ -I external/mcl/include/
#cgo CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4
#cgo bn256 LDFLAGS:-lbls256
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn384 LDFLAGS:-lbls384
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4
#cgo bn384_256 LDFLAGS:-lbls384_256
#cgo LDFLAGS:-L./external/bls/lib -lbls384
#cgo LDFLAGS:-lcrypto -lgmp -lgmpxx -lstdc++
#include "config.h"
#include <bls/bls.h>
*/
import "C"
import (
	"fmt"
	"log"
)
import "unsafe"

// Initialize the library automatically with the default curve BLS12_381
func init() {
	if err := InitializeBLS(BLS12_381); err != nil {
		log.Fatalf("Could not initialize BLS12-381 curve: %v", err)
	}
}

// Library users MUST call this function to use a different curve than BLS12_381 before calling any the other library func
// This function is not thread safe.
func InitializeBLS(curve int) error {
	err := C.blsInit(C.int(curve), C.MCLBN_COMPILED_TIME_VAR)
	if err != 0 {
		return fmt.Errorf("ERR Init curve=%d", curve)
	}
	return nil
}

// ---------------- ID Functions --------------------

type ID struct {
	v Fr
}

// getPointer returns a bls id pointer
func (id *ID) getPointer() (p *C.blsId) {
	// #nosec
	return (*C.blsId)(unsafe.Pointer(id))
}

// GetLittleEndian returns a little-endian encoded byte array
func (id *ID) GetLittleEndian() []byte {
	return id.v.Serialize()
}

// SetLittleEndian sets an id from a little-endian encoded byte array
func (id *ID) SetLittleEndian(buf []byte) error {
	return id.v.SetLittleEndian(buf)
}

// GetHexString returns a hex-formatted string encoding of the id
// This is the canonical representation of an id
func (id *ID) GetHexString() string {
	return id.v.GetString(16)
}

// GetDecString returns a decimal-formatted string encoding of id
func (id *ID) GetDecString() string {
	return id.v.GetString(10)
}

// SetHexString. Sets id from a hex-formatted string
// This is the canonical way to build an ID
func (id *ID) SetHexString(s string) error {
	return id.v.SetString(s, 16)
}

// SetDecString sets the id from a dec-formatted string
func (id *ID) SetDecString(s string) error {
	return id.v.SetString(s, 10)
}

// IsEqual returns true if and only if id equals rhs
func (id *ID) IsEqual(rhs *ID) bool {
	return id.v.IsEqual(&rhs.v)
}

// ---------------- Secret Key Functions --------------------

// SecretKey
type SecretKey struct {
	v Fr
}

// NewSecretKey returns a new random secret key
func NewSecretKey() SecretKey {
	k := SecretKey{}
	k.v.SetByCSPRNG()
	return k
}

// GetHexString returns a hex-formatted string of the secret key
// This is the canonical way to serialize a secret key
func (sec *SecretKey) GetHexString() string {
	return sec.v.GetString(16)
}

// SetHexString sets the key's value from a hex-formatted string
// This is the canonical way to deserialize a secret key
func (sec *SecretKey) SetHexString(s string) error {
	return sec.v.SetString(s, 16)
}

// getPointer returns a pointer to the secret key
func (sec *SecretKey) getPointer() (p *C.blsSecretKey) {
	// #nosec
	return (*C.blsSecretKey)(unsafe.Pointer(sec))
}

// GetLittleEndian returns a little-endian encoded byte array of the secret key
func (sec *SecretKey) GetLittleEndian() []byte {
	return sec.v.Serialize()
}

// SetLittleEndian sets the secret key from a little-endian encoded byte array
func (sec *SecretKey) SetLittleEndian(buf []byte) error {
	return sec.v.SetLittleEndian(buf)
}

// SerializeToHexStr serializes the key to a little-endian hex-formatted string
func (sec *SecretKey) SerializeToHexStr() string {
	return sec.v.GetString(IoSerializeHexStr)
}

// DeserializeHexStr creates a key from a little-endian hex-formatted string
func (sec *SecretKey) DeserializeHexStr(s string) error {
	return sec.v.SetString(s, IoSerializeHexStr)
}

// GetDecString returns a decimal-formatted string of the secret key
func (sec *SecretKey) GetDecString() string {
	return sec.v.GetString(10)
}

// SetDecString sets the secret key from a decimal-formatted string
func (sec *SecretKey) SetDecString(s string) error {
	return sec.v.SetString(s, 10)
}

// IsEqual returns true if and only if two secret keys are the same key (bls keys are unique)
func (sec *SecretKey) IsEqual(rhs *SecretKey) bool {
	return sec.v.IsEqual(&rhs.v)
}

// SetByCSPRNG sets secret key to a random value
func (sec *SecretKey) SetByCSPRNG() {
	sec.v.SetByCSPRNG()
}

// Add aggregates 2 secret keys
func (sec *SecretKey) Add(rhs *SecretKey) {
	FrAdd(&sec.v, &sec.v, &rhs.v)
}

// GetMasterSecretKey
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].SetByCSPRNG()
	}
	return msk
}

// Set --
func (sec *SecretKey) Set(msk []SecretKey, id *ID) error {
	// #nosec
	return FrEvaluatePolynomial(&sec.v, *(*[]Fr)(unsafe.Pointer(&msk)), &id.v)
}

// Recover --
func (sec *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	// #nosec
	return FrLagrangeInterpolation(&sec.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]Fr)(unsafe.Pointer(&secVec)))
}

// GetPop --
func (sec *SecretKey) GetPop() (sign *Sign) {
	sign = new(Sign)
	C.blsGetPop(sign.getPointer(), sec.getPointer())
	return sign
}

// ---------------- Public Key --------------------

// PublicKey
type PublicKey struct {
	v G2
}

// GetMasterPublicKey
func GetMasterPublicKey(msk []SecretKey) (mpk []PublicKey) {
	n := len(msk)
	mpk = make([]PublicKey, n)
	for i := 0; i < n; i++ {
		mpk[i] = *msk[i].GetPublicKey()
	}
	return mpk
}

// getPointer --
func (pub *PublicKey) getPointer() (p *C.blsPublicKey) {
	// #nosec
	return (*C.blsPublicKey)(unsafe.Pointer(pub))
}

// Serialize -- get rat bytes
func (pub *PublicKey) Serialize() []byte {
	return pub.v.Serialize()
}

// Deserialize -- from raw bytes
func (pub *PublicKey) Deserialize(buf []byte) error {
	return pub.v.Deserialize(buf)
}

// SerializeToHexStr -- BigEndian hex of raw bytes
func (pub *PublicKey) SerializeToHexStr() string {
	return pub.v.GetString(IoSerializeHexStr)
}

// DeserializeHexStr -- From bigEndian hex string
func (pub *PublicKey) DeserializeHexStr(s string) error {
	return pub.v.SetString(s, IoSerializeHexStr)
}

// GetHexString --
func (pub *PublicKey) GetHexString() string {
	return pub.v.GetString(16)
}

// SetHexString --
func (pub *PublicKey) SetHexString(s string) error {
	return pub.v.SetString(s, 16)
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	return pub.v.IsEqual(&rhs.v)
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	G2Add(&pub.v, &pub.v, &rhs.v)
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	// #nosec
	return G2EvaluatePolynomial(&pub.v, *(*[]G2)(unsafe.Pointer(&mpk)), &id.v)
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	// #nosec
	return G2LagrangeInterpolation(&pub.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G2)(unsafe.Pointer(&pubVec)))
}

// Sign  --
type Sign struct {
	v G1
}

// getPointer --
func (sign *Sign) getPointer() (p *C.blsSignature) {
	// #nosec
	return (*C.blsSignature)(unsafe.Pointer(sign))
}

// Serialize --
func (sign *Sign) Serialize() []byte {
	return sign.v.Serialize()
}

// Deserialize --
func (sign *Sign) Deserialize(buf []byte) error {
	return sign.v.Deserialize(buf)
}

// SerializeToHexStr --
func (sign *Sign) SerializeToHexStr() string {
	return sign.v.GetString(IoSerializeHexStr)
}

// DeserializeHexStr --
func (sign *Sign) DeserializeHexStr(s string) error {
	return sign.v.SetString(s, IoSerializeHexStr)
}

// GetHexString --
func (sign *Sign) GetHexString() string {
	return sign.v.GetString(16)
}

// SetHexString --
func (sign *Sign) SetHexString(s string) error {
	return sign.v.SetString(s, 16)
}

// IsEqual --
func (sign *Sign) IsEqual(rhs *Sign) bool {
	return sign.v.IsEqual(&rhs.v)
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(pub.getPointer(), sec.getPointer())
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(message []byte) (sign *Sign) {
	sign = new(Sign)
	// #nosec
	C.blsSign(sign.getPointer(), sec.getPointer(), unsafe.Pointer(&message[0]), C.size_t(len(message)))
	return sign
}

// SignHash
// use the low (bitSize of r) - 1 bit of h
// return 0 if success else -1
// NOTE : return false if h is zero or c1 or -c1 value for BN254. see hashTest() in test/bls_test.hpp
func (sec *SecretKey) SignHash(hash []byte) (sign *Sign) {
	sign = new(Sign)
	// #nosec
	if C.blsSignHash(sign.getPointer(), sec.getPointer(), unsafe.Pointer(&hash[0]), C.size_t(len(hash))) != 0 {
		// todo: handle error
	}
	return sign
}

// Add --
func (sign *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(sign.getPointer(), rhs.getPointer())
}

// Recover --
func (sign *Sign) Recover(signVec []Sign, idVec []ID) error {
	// #nosec
	return G1LagrangeInterpolation(&sign.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G1)(unsafe.Pointer(&signVec)))
}

// Verify --
func (sign *Sign) Verify(pub *PublicKey, message []byte) bool {
	// #nosec
	return C.blsVerify(sign.getPointer(), pub.getPointer(), unsafe.Pointer(&message[0]), C.size_t(len(message))) == 1
}

// VerifyPop --
func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsVerifyPop(sign.getPointer(), pub.getPointer()) == 1
}

// DHKeyExchange --
func DHKeyExchange(sec *SecretKey, pub *PublicKey) (out PublicKey) {
	C.blsDHKeyExchange(out.getPointer(), sec.getPointer(), pub.getPointer())
	return out
}

// Verify aggregated signature created by n entities each signing a hash of a different messages
// publicKeys - n public keys
// hashes - n hashes of messages, each hSize long
// n - number of signers
//
//     e(aggSig, Q) = prod_i e(hVec[i], pubVec[i])
//
// return 1 if valid
// @note does not check duplication of hVec
func (sign *Sign) VerifyAggregatedHashes(pubKeys []PublicKey, hashes []byte, hSize uint, n uint) bool {

	if n == 0 || uint(len(pubKeys)) != n || uint(len(hashes)) != n*hSize || hSize == 0 {
		return false
	}

	return C.blsVerifyAggregatedHashes(
		sign.getPointer(),
		pubKeys[0].getPointer(),
		unsafe.Pointer(&hashes[0]),
		C.size_t(hSize),
		C.ulong(n)) == 1
}
