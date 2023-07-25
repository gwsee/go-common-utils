package primitives

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	//hcrypto "git.hyperchain.cn/dmlab/go-common-utils/certgen/crypto"
)

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// NewECDSAKey generates a new ECDSA Key
func NewECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(GetDefaultCurve(), rand.Reader)
}

// ECDSASignDirect signs
func ECDSASignDirect(signKey interface{}, msg []byte) (*big.Int, *big.Int, error) {
	temp := signKey.(*ecdsa.PrivateKey)
	h := Hash(msg)
	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

// ECDSASign signs
//func ECDSASign(signKey interface{}, msg []byte) ([]byte, error) {
//	temp := signKey.(*ecdsa.PrivateKey)
//
//	//修改hash方法
//	hasher := hcrypto.NewKeccak256Hash("keccak256Hanser")
//	h := hasher.Hash(msg).Bytes()
//	//h := Hash(msg)
//
//	//log.Error("Hash:",h)
//
//	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
//	if err != nil {
//		return nil, err
//	}
//
//	//	R, _ := r.MarshalText()
//	//	S, _ := s.MarshalText()
//	//
//	//	fmt.Printf("r [%s], s [%s]\n", R, S)
//
//	raw, err := asn1.Marshal(ECDSASignature{r, s})
//	if err != nil {
//		return nil, err
//	}
//
//	return raw, nil
//}

// ECDSAVerify verifies
//func ECDSAVerify(verKey interface{}, msg, signature []byte) (bool, error) {
//	ecdsaSignature := new(ECDSASignature)
//	_, err := asn1.Unmarshal(signature, ecdsaSignature)
//	if err != nil {
//		return false, nil
//	}
//
//	//	R, _ := ecdsaSignature.R.MarshalText()
//	//	S, _ := ecdsaSignature.S.MarshalText()
//	//	fmt.Printf("r [%s], s [%s]\n", R, S)
//
//	temp := verKey.(ecdsa.PublicKey)
//	hasher := hcrypto.NewKeccak256Hash("keccak256Hanse")
//	h := hasher.Hash(msg).Bytes()
//	//h := Hash(msg)
//	return ecdsa.Verify(&temp, h, ecdsaSignature.R, ecdsaSignature.S), nil
//}
