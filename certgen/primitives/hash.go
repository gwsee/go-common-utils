//Hyperchain License
//Copyright (C) 2016 The Hyperchain Authors.
package primitives

import (
	"crypto/hmac"
	"hash"
)

var (
	defaultHash          func() hash.Hash
	defaultHashAlgorithm string
)

// GetDefaultHash returns the default hash function used by the crypto layer
func GetDefaultHash() func() hash.Hash {
	return defaultHash
}

// GetHashAlgorithm return the default hash algorithm
func GetHashAlgorithm() string {
	return defaultHashAlgorithm
}

// NewHash returns a new hash function
func NewHash() hash.Hash {
	return GetDefaultHash()()
}

// Hash hashes the msh using the predefined hash function
func Hash(msg []byte) []byte {
	hash := NewHash()

	hash.Write(msg)
	return hash.Sum(nil)
}

// HMAC hmacs x using key key
func HMAC(key, x []byte) []byte {
	mac := hmac.New(GetDefaultHash(), key)
	mac.Write(x)

	return mac.Sum(nil)
}

// HMACTruncated hmacs x using key key and truncate to truncation
func HMACTruncated(key, x []byte, truncation int) []byte {
	mac := hmac.New(GetDefaultHash(), key)
	mac.Write(x)

	return mac.Sum(nil)[:truncation]
}

// HMACAESTruncated hmacs x using key key and truncate to AESKeyLength
//func HMACAESTruncated(key, x []byte) []byte {
//	return HMACTruncated(key, x, AESKeyLength)
//}
