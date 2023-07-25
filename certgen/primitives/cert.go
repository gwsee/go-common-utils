package primitives

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/op/go-logging"

	"git.hyperchain.cn/dmlab/go-common-utils/certgen/guomi/sm2"
	gmx509 "git.hyperchain.cn/dmlab/go-common-utils/certgen/primitives/x509"
	"git.hyperchain.cn/dmlab/go-common-utils/certgen/primitives/x509/pkix"
)

var (
	defaultCurve elliptic.Curve
	log          = logging.MustGetLogger("crypto")
)

func init() {
	//secp256r1 a.k.a P256
	defaultCurve = elliptic.P256()
}

// GetDefaultCurve returns the default elliptic curve used by the crypto layer
func GetDefaultCurve() elliptic.Curve {
	return defaultCurve
}

//// PrivateKeyToDER marshals a private key to der
//func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
//	if privateKey == nil {
//		return nil, ErrNilArgument
//	}
//	return x509.MarshalECPrivateKey(privateKey)
//}

func PublicKeyToDER(publicKey *ecdsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrNilArgument
	}
	return x509.MarshalPKIXPublicKey(publicKey)
}

// DERToPrivateKey unmarshals a der to private key
//func DERToPrivateKey(der []byte) (key interface{}, err error) {
//	//fmt.Printf("DER [%s]\n", EncodeBase64(der))
//
//	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
//		return key, nil
//	}
//	//fmt.Printf("DERToPrivateKey Err [%s]\n", err)
//	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
//		switch key.(type) {
//		case *rsa.PrivateKey, *ecdsa.PrivateKey:
//			return
//		default:
//			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
//		}
//	}
//	//fmt.Printf("DERToPrivateKey Err [%s]\n", err)
//	if key, err = x509.ParseECPrivateKey(der); err == nil {
//		return
//	}
//	//fmt.Printf("DERToPrivateKey Err [%s]\n", err)
//
//	return nil, errors.New("Failed to parse private key")
//}

// DERCertToPEM converts der to pem
func DERCertToPEM(der []byte) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)
}

// DERToX509Certificate converts der to x509
func DERToX509Certificate(asn1Data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(asn1Data)
}

//解析证书
func ParseCertificate(cert []byte) (*gmx509.Certificate, error) {
	block, _ := pem.Decode(cert)

	if block == nil {
		fmt.Println("failed to parse certificate PEM")
		return nil, errors.New("failed to parse certificate PEM")
	}

	x509Cert, err := gmx509.ParseCertificate(block.Bytes)

	if err != nil {
		fmt.Println("faile to parse certificate")
		return nil, errors.New("faile to parse certificate")
	}

	return x509Cert, nil
}

//// DERToPublicKey unmarshals a der to public key
//func DERToPublicKey(derBytes []byte) (pub interface{}, err error) {
//	key, err := x509.ParsePKIXPublicKey(derBytes)
//
//	return key, err
//}

//创建通过ca证书签发新证书
func CreateCertByCa(ca *gmx509.Certificate, caPrivate interface{}, certType gmx509.CertType, isCa bool) (certDER []byte,
	subPriv interface{}, err error) {
	var (
		signatureAlgorithm gmx509.SignatureAlgorithm
		subPrivKey         interface{}
		subPubKey          interface{}
		useGuomi           bool
	)

	//这里的逻辑是，如果ca的私钥是guomi的，则生成的cert的共私钥也是国密的。反之亦然。
	switch caPrivate.(type) {
	case *sm2.PrivateKey:
		useGuomi = true
		signatureAlgorithm = gmx509.SM3WithSM2
		subPriv, err := GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		subPrivKey = subPriv
		subPubKey = subPriv.Public()
	case *ecdsa.PrivateKey:
		useGuomi = false
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		subPriv, err := NewECDSAKey()
		if err != nil {
			return nil, nil, err
		}
		subPrivKey = subPriv
		subPubKey = subPriv.Public()
	default:
		return nil, nil, errors.New("private neither *gmx509.PrivateKey nor *ecdsa.PrivateKey")
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	commonName := "hyperchain.cn"
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Develop",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}
	if certType != gmx509.UnknownCertType {
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{
				Id:    gmx509.CertTypeOID,
				Value: certType.GetValue(),
			})
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, ca, subPubKey, caPrivate, useGuomi)
	if err != nil {
		return nil, nil, err
	}
	return cert, subPrivKey, nil
}

//创建通过ca证书签发新证书
//如果ca是国密的，则这里要求提供的subPublic也是国密的
func CreateCertByCaAndPublicKey(ca *gmx509.Certificate, caPrivate interface{}, subPublic interface{},
	certType gmx509.CertType, isCa bool) (certDER []byte, err error) {
	var (
		signatureAlgorithm gmx509.SignatureAlgorithm
		useGuomi           bool
	)

	//这里的逻辑是，如果ca的私钥是guomi的，则生成的cert的共私钥也是国密的。反之亦然。
	switch caPrivate.(type) {
	case *sm2.PrivateKey:
		useGuomi = true
		signatureAlgorithm = gmx509.SM3WithSM2
	case *ecdsa.PrivateKey:
		useGuomi = false
		signatureAlgorithm = gmx509.ECDSAWithSHA256
	default:
		return nil, errors.New("private neither *gmx509.PrivateKey nor *ecdsa.PrivateKey")
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	commonName := "hyperchain.cn"
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Develop",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}

	if certType != gmx509.UnknownCertType {
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{
				Id:    gmx509.CertTypeOID,
				Value: certType.GetValue(),
			})
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, ca, subPublic, caPrivate, useGuomi)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

//生成自签名证书
func NewSelfSignedCert(useGuomi bool) ([]byte, interface{}, error) {
	var (
		err                error
		privKeyECDSA       *ecdsa.PrivateKey
		privKeySM          *sm2.PrivateKey
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            interface{}
		pubKey             interface{}
	)
	if useGuomi {
		privKeySM, err = GenerateKey()
		signatureAlgorithm = gmx509.SM3WithSM2
		privKey = privKeySM
		pubKey = privKeySM.Public()
	} else {
		privKeyECDSA, err = NewECDSAKey()
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		privKey = privKeyECDSA
		pubKey = privKeyECDSA.Public()
	}

	if err != nil {
		return nil, nil, err
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	//extraExtensionData := []byte("extra extension")
	commonName := "hyperchain.cn"
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Develop",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		//OCSPServer:            []string{"http://ocsp.example.com"},
		//IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		//DNSNames:       []string{"test.example.com"},
		//EmailAddresses: []string{"gopher@golang.org"},
		//IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		//PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		//PermittedDNSDomains: []string{".example.com", "example.com"},

		//CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		//ExtraExtensions: []pkix.Extension{
		//	{
		//		Id:    []int{1, 2, 3, 4},
		//		Value: extraExtensionData,
		//	},
		//},
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey, useGuomi)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

//生成自签名证书
func NewSelfSignedCertByJSON(useGuomi bool, priv *sm2.PrivateKey) ([]byte, interface{}, error) {
	var (
		err error
		//privKeyECDSA       *ecdsa.PrivateKey
		//privKeySM          *gmx509.PrivateKey
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            interface{}
		pubKey             interface{}
	)
	//if useGuomi {
	//privKeySM, err = GenerateKey()
	signatureAlgorithm = gmx509.SM3WithSM2
	privKey = priv
	pubKey = priv.Public()
	//} else {
	//	privKeyECDSA, err = NewECDSAKey()
	//	signatureAlgorithm = gmx509.ECDSAWithSHA256
	//	privKey = privKeyECDSA
	//	pubKey = privKeyECDSA.Public()
	//}

	if err != nil {
		return nil, nil, err
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	commonName := "hyperchain.cn"
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Develop",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey, useGuomi)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

//解析PEM私钥
func ParsePriKey(derPri string) (interface{}, error) {
	block, _ := pem.Decode([]byte(derPri))

	pri, err1 := DERToPrivateKey(block.Bytes)

	if err1 != nil {
		return nil, err1
	}

	return pri, nil
}

//解析PEM公钥
func ParsePubKey(pubstr string) (*ecdsa.PublicKey, error) {
	if pubstr == "" {
		return nil, errors.New("the pub pem is nil")
	}
	block, _ := pem.Decode([]byte(pubstr))
	pub, err := DERToPublicKey(block.Bytes)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	pubkey := pub.(*(ecdsa.PublicKey))

	return pubkey, nil
}

//产生私钥PEM文件
func GenPrivateKeyPem(path string, key interface{}) error {
	switch v := key.(type) {
	case *sm2.PrivateKey:
		WritePrivateKeytoPem(path, v, nil)
		return nil
	case *ecdsa.PrivateKey:
		var block pem.Block
		block.Type = "EC PRIVATE KEY"
		der, _ := PrivateKeyToDER(v)
		block.Bytes = der
		file, _ := os.Create(path)
		pem.Encode(file, &block)
		return nil
	default:
		return errors.New("key is neither *gmx509.PrivateKey nor *ecdsa.PrivateKey")
	}
}

func GetConfig(path string) ([]byte, error) {
	content, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	return content, nil

}

func VerifyCert(cert *gmx509.Certificate, ca *gmx509.Certificate) (bool, error) {
	err := cert.CheckSignatureFrom(ca)

	// ErrCertExpired := errors.New("Cert expired")
	if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
		log.Error("Cert expired.")
		return false, errors.New("Cert expired.")
	}

	// ErrCertInvalid := errors.New("Failed to validate cert", err)
	if err != nil {
		log.Error("Failed to validate cert", err)
		return false, err
	}

	return true, nil
}

func ParseKey(derPri []byte) (interface{}, error) {
	block, _ := pem.Decode(derPri)
	pri, err1 := DERToPrivateKey(block.Bytes)

	if err1 != nil {
		return nil, err1
	}

	return pri, nil
}
