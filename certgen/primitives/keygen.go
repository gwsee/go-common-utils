package primitives

// reference to ecdsa
import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"os"

	"git.hyperchain.cn/dmlab/go-common-utils/certgen/common"
	"git.hyperchain.cn/dmlab/go-common-utils/certgen/guomi"
	"git.hyperchain.cn/dmlab/go-common-utils/certgen/guomi/sm2"
	"git.hyperchain.cn/dmlab/go-common-utils/certgen/primitives/x509/pkix"
)

var (
	oidSM2               = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256Sm2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidKEYSHA1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidPBKDF2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidPBES2             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
)

func GenerateKey() (*sm2.PrivateKey, error) {
	c := guomi.P256Sm2()
	k, err := RandFieldElement(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func RandFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

type sm2PrivateKeyCFCA struct {
	Version       int
	PrivateKey    *big.Int
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type sm2PrivateKeyGmssl struct {
	Version       int
	PrivateKey    asn1.RawContent
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

//ParseSMPrivateKey 解析国密私钥，不论gmssl产生的私钥或者cfca的私钥，返回gmx509.PrivateKey类型
func ParseSMPrivateKey(der []byte) (interface{}, error) {
	var privGmssl sm2PrivateKeyGmssl
	var privCFCA sm2PrivateKeyCFCA
	_, err := asn1.Unmarshal(der, &privGmssl)
	if err == nil { //如果err为nil.说明解析成功
		if !privGmssl.NamedCurveOID.Equal(oidNamedCurveP256Sm2) {
			return nil, errors.New("is not SM Private key")
		}
		x, y := elliptic.Unmarshal(guomi.P256Sm2(), privGmssl.PublicKey.Bytes)
		return &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: guomi.P256Sm2(),
				X:     x,
				Y:     y,
			},
			D: common.BytesToBig(privGmssl.PrivateKey),
		}, nil
	}

	err = nil
	_, err = asn1.Unmarshal(der, &privCFCA)
	if err == nil { //如果err为nil.说明解析成功
		if !privCFCA.NamedCurveOID.Equal(oidNamedCurveP256Sm2) {
			return nil, errors.New("is not SM Private key")
		}
		x, y := elliptic.Unmarshal(guomi.P256Sm2(), privCFCA.PublicKey.Bytes)
		return &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: guomi.P256Sm2(),
				X:     x,
				Y:     y,
			},
			D: privCFCA.PrivateKey,
		}, nil
	}

	return nil, errors.New("is not SM Private key")
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func MarshalSm2PublicKey(key *sm2.PublicKey) ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	return asn1.Marshal(r)
}

func MarshalSm2UnecryptedPrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	//var r pkcs8
	var priv sm2PrivateKeyGmssl
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256Sm2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = asn1.RawContent(key.D.Bytes())
	//r.Version = 0
	//r.Algo = algo
	//r.PrivateKey, _ = asn1.Marshal(priv)
	//return asn1.Marshal(r)
	return asn1.Marshal(priv)
}

func MarshalSm2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	if pwd == nil {
		return MarshalSm2UnecryptedPrivateKey(key)
	}
	return MarshalSm2EcryptedPrivateKey(key, pwd)
}

func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

type Pbes2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm Pbes2Algorithms
	EncryptedData       []byte
}

type Pkdf2Params struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}

type Pbes2Params struct {
	KeyDerivationFunc Pbes2KDfs
	EncryptionScheme  Pbes2Encs
}

type Pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params Pbes2Params
}

type Pbes2KDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params Pkdf2Params
}

func MarshalSm2EcryptedPrivateKey(PrivKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	der, err := MarshalSm2UnecryptedPrivateKey(PrivKey)
	if err != nil {
		return nil, err
	}
	iter := 2048
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	rand.Reader.Read(salt)
	rand.Reader.Read(iv)
	key := pbkdf(pwd, salt, iter, 32, sha1.New) // 默认是SHA1
	padding := aes.BlockSize - len(der)%aes.BlockSize
	if padding > 0 {
		n := len(der)
		der = append(der, make([]byte, padding)...)
		for i := 0; i < padding; i++ {
			der[n+i] = byte(padding)
		}
	}
	encryptedKey := make([]byte, len(der))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, der)
	var algorithmIdentifier pkix.AlgorithmIdentifier
	algorithmIdentifier.Algorithm = oidKEYSHA1
	algorithmIdentifier.Parameters.Tag = 5
	algorithmIdentifier.Parameters.IsCompound = false
	algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	keyDerivationFunc := Pbes2KDfs{
		oidPBKDF2,
		Pkdf2Params{
			salt,
			iter,
			algorithmIdentifier,
		},
	}
	encryptionScheme := Pbes2Encs{
		oidAES256CBC,
		iv,
	}
	pbes2Algorithms := Pbes2Algorithms{
		oidPBES2,
		Pbes2Params{
			keyDerivationFunc,
			encryptionScheme,
		},
	}
	encryptedPkey := EncryptedPrivateKeyInfo{
		pbes2Algorithms,
		encryptedKey,
	}
	return asn1.Marshal(encryptedPkey)
}

//WritePrivateKeytoPem 产生国密私钥
func WritePrivateKeytoPem(FileName string, key *sm2.PrivateKey, pwd []byte) (bool, error) {
	var block *pem.Block
	// 直接改为UnencryptedKey
	der, err := MarshalSm2PrivateKey(key, pwd)
	if err != nil {
		return false, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

func WritePublicKeytoPem(FileName string, key *sm2.PublicKey, _ []byte) (bool, error) {
	der, err := MarshalSm2PublicKey(key)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	defer file.Close()
	if err != nil {
		return false, err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

//产生国密私钥对
func GenKeyPairPem(privPath string, pubPath string) error {
	priv, err := GenerateKey()
	if err != nil {
		return err
	}
	_, err = WritePrivateKeytoPem(privPath, priv, nil)
	if err != nil {
		return err
	}
	publicKey := priv.Public().(*sm2.PublicKey)
	_, err = WritePublicKeytoPem(pubPath, publicKey, nil)
	if err != nil {
		return err
	}
	return nil
}
