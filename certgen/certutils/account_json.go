package certutils

import (
	"bytes"
	"crypto/des"
	"encoding/json"
	"errors"

	"github.com/gwsee/go-common-utils/certgen/common"
	"github.com/gwsee/go-common-utils/certgen/guomi"
	"github.com/gwsee/go-common-utils/certgen/guomi/sm2"
	"github.com/gwsee/go-common-utils/certgen/primitives"
)

type accountJSON struct {
	Address string `json:"address"`
	// Algo 0x01 KDF2 0x02 DES(ECB) 0x03(plain) 0x04 DES(CBC)
	Algo                string `json:"algo,omitempty"`
	Encrypted           string `json:"encrypted,omitempty"`
	Version             string `json:"version,omitempty"`
	PublicKey           string `json:"publicKey,omitempty"`
	PrivateKey          string `json:"privateKey,omitempty"`
	PrivateKeyEncrypted bool   `json:"privateKeyEncrypted"`
}

// NewAccountFromAccountJSON ECDSA Key结构体
func CAFromAccountJSON(accountjson, password string) ([]byte, *sm2.PrivateKey, error) {
	account := new(accountJSON)
	err := json.Unmarshal([]byte(accountjson), account)
	if err != nil {
		return nil, nil, err
	}
	if common.HasHexPrefix(account.Address) {
		account.Address = account.Address[2:]
	}

	priv := new(sm2.PrivateKey)
	pubAll := common.Hex2Bytes(account.PublicKey)
	length := len(pubAll)
	x := pubAll[1 : length/2+1]
	y := pubAll[length/2+1:]
	priv.X = common.Bytes2Big(x)
	priv.Y = common.Bytes2Big(y)

	b := common.Hex2Bytes(account.PrivateKey)
	if account.PrivateKeyEncrypted {
		if password == "" {
			return nil, nil, errors.New("accountJSON is Encrypted, but don't have password")
		}
		b, _ = DesDecrypt(common.Hex2Bytes(account.PrivateKey), []byte(password))
	}
	priv.D = common.BytesToBig(b)
	priv.Curve = guomi.P256Sm2()

	der, _, err := primitives.NewSelfSignedCertByJSON(true, priv)
	if err != nil {
		return nil, nil, err
	}
	pem := primitives.DERCertToPEM(der)
	return pem, priv, nil
}

func DesDecrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) < 8 {
		key = ZeroPadding(key, 8)
	} else {
		key = key[0:8]
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out, nil
}
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{48}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//func getAddressFromCert(rawcert []byte) ([]byte, error) {
//	cert, err := primitives.ParseCertificate(rawcert)
//	if err != nil {
//		return nil, err
//	}
//	var publick []byte
//	switch pub := cert.PublicKey.(type) {
//	case *ecdsa.PublicKey:
//		publick = append(pub.X.Bytes(), pub.Y.Bytes()...)
//	case *sm2.PublicKey:
//		publick = append(pub.X.Bytes(), pub.Y.Bytes()...)
//	default:
//
//	}
//	hasher := crypto.NewKeccak256Hash("keccak256Hasher")
//	return hasher.ByteHash(publick).Bytes()[12:], nil
//}
