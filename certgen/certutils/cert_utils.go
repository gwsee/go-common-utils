package certutils

import (
	"crypto/ecdsa"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gwsee/go-common-utils/certgen/guomi/sm2"
	"github.com/gwsee/go-common-utils/certgen/primitives"
	gmx509 "github.com/gwsee/go-common-utils/certgen/primitives/x509"
	"github.com/pkg/errors"
)

//自己生成根证书 ok
func SelfSignCA(useGuomi bool, selfCAPath string, selfCAPrivPath string) error {
	der, pri, err := primitives.NewSelfSignedCert(useGuomi)
	if err != nil {
		return err
	}
	certPemByte := primitives.DERCertToPEM(der)
	file, err := os.Create(selfCAPath)
	if err != nil {
		return err
	}
	file.WriteString(string(certPemByte))
	if useGuomi {
		primitives.WritePrivateKeytoPem(selfCAPrivPath, pri.(*sm2.PrivateKey), nil)
	} else {
		var block pem.Block
		block.Type = "EC PRIVATE KEY"
		priv := pri.(*ecdsa.PrivateKey)
		der, err = primitives.PrivateKeyToDER(priv)
		if err != nil {
			return err
		}
		block.Bytes = der
		file, err = os.Create(selfCAPrivPath)
		if err != nil {
			return err
		}
		pem.Encode(file, &block)
	}
	return nil
}

func IsCA(certPath string) (bool, error) {
	fileContent, err := ioutil.ReadFile(certPath)
	if err != nil {
		return false, err
	}
	certStr := string(fileContent)
	block, _ := pem.Decode([]byte(certStr))
	cert, err := gmx509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	return cert.IsCA, nil
}

//检查pem格式的证书的合法性 ok
func CheckCertSignature(certPath string) error {
	fileContent, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}
	//block, _ := pem.Decode(fileContent)
	cert, _ := primitives.ParseCertificate(fileContent)
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	return err
}

//生成私钥pem格式文件 ok
func GeneratePrivKeyFile(privPath string, pubPath string, useGuomi bool) error {
	var (
		priSM2   *sm2.PrivateKey
		priECDSA *ecdsa.PrivateKey
	)
	if useGuomi {
		priSM2, _ = primitives.GenerateKey()

	} else {
		priECDSA, _ = primitives.NewECDSAKey()
	}

	fmt.Println("===============")
	fmt.Println("生成私钥为：")
	if useGuomi {
		fmt.Println("guomi:")
		fmt.Println(priSM2.D)
	} else {
		fmt.Println("ecdsa:")
		fmt.Println(priECDSA.D)
	}
	fmt.Println("===============")

	fmt.Println("===============")
	fmt.Println("生成公钥为：")
	if useGuomi {
		fmt.Println("x:", priSM2.Public().(*sm2.PublicKey).X)
		fmt.Println("y:", priSM2.Public().(*sm2.PublicKey).Y)
	} else {
		fmt.Println(priECDSA.Public())
	}
	fmt.Println("===============")
	var blockPri pem.Block
	var blockPub pem.Block
	blockPri.Type = "EC PRIVATE KEY"
	blockPub.Type = "EC PUBLIC KEY"
	if useGuomi {
		_, err := primitives.WritePrivateKeytoPem(privPath, priSM2, nil)
		if err != nil {
			return err
		}
		publicKey := priSM2.Public().(*sm2.PublicKey)
		_, err = primitives.WritePublicKeytoPem(pubPath, publicKey, nil)
		if err != nil {
			return err
		}
		return nil
	}
	derPri, errPri := primitives.PrivateKeyToDER(priECDSA)
	derPub, errPub := primitives.PublicKeyToDER(&priECDSA.PublicKey)
	if errPri != nil {
		return errPri
	}
	if errPub != nil {
		return errPub
	}
	blockPri.Bytes = derPri
	blockPub.Bytes = derPub
	filePri, errPri := os.Create(privPath)
	filePub, errPub := os.Create(pubPath)
	if errPri != nil {
		return errPri
	}
	if errPub != nil {
		return errPub
	}
	pem.Encode(filePri, &blockPri)
	pem.Encode(filePub, &blockPub)
	return nil
}

// 生成私钥pem格式内容
func GeneratePrivKey() ([]byte, error) {
	pri, _ := primitives.NewECDSAKey()
	fmt.Println("===============")
	fmt.Println("生成私钥为：")
	fmt.Println(pri)
	fmt.Println("===============")

	//fmt.Println(json)
	var block pem.Block
	block.Type = "EC PRIVATE KEY"
	der, err := primitives.PrivateKeyToDER(pri)
	if err != nil {
		return nil, err
	}
	block.Bytes = der
	pribyte := pem.EncodeToMemory(&block)
	return pribyte, nil
}

func GetPubFromPrivatePEM(privPath, pubPath string) error {
	if pri, err := ParsePrivateKey(privPath); err == nil {
		switch privateKey := pri.(type) {
		case *ecdsa.PrivateKey:
			var blockPub pem.Block
			blockPub.Type = "EC PUBLIC KEY"
			derPub, errPub := primitives.PublicKeyToDER(&privateKey.PublicKey)
			if errPub != nil {
				return errPub
			}
			blockPub.Bytes = derPub
			filePub, errPub := os.Create(pubPath)
			if errPub != nil {
				return errPub
			}
			pem.Encode(filePub, &blockPub)
			return nil
		case *sm2.PrivateKey:
			_, err = primitives.WritePublicKeytoPem(pubPath, privateKey.Public().(*sm2.PublicKey), nil)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return errors.New("Cannot decode the privateKey")
}

//解析PEM格式的私钥
func ParsePrivateKey(privPath string) (key interface{}, err error) {
	content, _ := ioutil.ReadFile(privPath)
	privateKey := string(content)
	block, _ := pem.Decode([]byte(privateKey))
	//var pri ecdsa.PrivateKey
	return primitives.DERToPrivateKey(block.Bytes)
}

//生成证书 ok
func CreateCert(rootCertPath string, rootCertPrivPath string, targetCertPath string, tarCertPrivPath string,
	certType string, isCa bool) error {
	rootCertByte, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return err
	}

	rootCert, err := primitives.ParseCertificate(rootCertByte)
	if err != nil {
		return err
	}
	rootCertPrivateKeyByte, err := ioutil.ReadFile(rootCertPrivPath)
	if err != nil {
		return err
	}

	rootCertPrivateKeyBlock, _ := pem.Decode(rootCertPrivateKeyByte)
	rootCertPrivateKey, err := primitives.DERToPrivateKey(rootCertPrivateKeyBlock.Bytes)
	if err != nil {
		return err
	}

	//解析证书类型
	t := gmx509.NewCertType(certType)
	if certType != "" && t == gmx509.UnknownCertType {
		return errors.New("type must be empty or one of: ecert, rcert, tcert or sdkcert")
	}
	certByCa, privateKey, err := primitives.CreateCertByCa(rootCert, rootCertPrivateKey, t, isCa)
	if err != nil {
		return err
	}

	certByCaPem := primitives.DERCertToPEM(certByCa)
	//写cert文件
	file, err := os.Create(targetCertPath)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(string(certByCaPem))

	//写私钥文件
	err = primitives.GenPrivateKeyPem(tarCertPrivPath, privateKey)
	if err != nil {
		return err
	}
	//验证证书
	certByCaX509, err := primitives.ParseCertificate(certByCaPem)
	if err != nil {
		return err
	}
	//ecertByCa1 := ParseCertificate()
	//pub1 := certByCaX509.PublicKey.(*ecdsa.PublicKey)
	//fmt.Println(*pub1)
	fmt.Println("---------PAST DUE---------")
	fmt.Println("subcert: ", certByCaX509.NotAfter)
	fmt.Println("rootcert: ", rootCert.NotAfter)
	fmt.Println("--------------------------")
	_, err = primitives.VerifyCert(certByCaX509, rootCert)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

//依据公钥生成证书
func CreateCertWithPublicKey(rootCertPath string, rootCertPrivPath string, tarCertPubPath string, targetCertPath string,
	certType string, isCa bool) error {

	rootCertByte, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return err
	}

	targetPubByte, err := ioutil.ReadFile(tarCertPubPath)
	if err != nil {
		return err
	}

	rootCert, err := primitives.ParseCertificate(rootCertByte)
	if err != nil {
		return err
	}
	rootCertPrivateKeyByte, err := ioutil.ReadFile(rootCertPrivPath)
	if err != nil {
		return err
	}

	rootCertPrivateKeyBlock, _ := pem.Decode(rootCertPrivateKeyByte)

	rootCertPrivateKey, err := primitives.DERToPrivateKey(rootCertPrivateKeyBlock.Bytes)
	if err != nil {
		return err
	}

	targetPublicKeyDER, _ := pem.Decode(targetPubByte)

	targetPublicKey, err := primitives.DERToPublicKey(targetPublicKeyDER.Bytes)
	if err != nil {
		return err
	}
	//解析证书类型
	t := gmx509.NewCertType(certType)
	if certType != "" && t == gmx509.UnknownCertType {
		return errors.New("type must be empty or one of: ecert, rcert, tcert or sdkcert")
	}
	targetCert, err := primitives.CreateCertByCaAndPublicKey(rootCert, rootCertPrivateKey, targetPublicKey, t, isCa)

	if err != nil {
		return err
	}

	certByCaPem := primitives.DERCertToPEM(targetCert)
	//写cert文件
	file, err := os.Create(targetCertPath)
	if err != nil {
		return err
	}
	file.WriteString(string(certByCaPem))

	//验证证书
	certByCaX509, err := primitives.ParseCertificate(certByCaPem)
	if err != nil {
	}
	//ecertByCa1 := ParseCertificate()
	//pub1 := certByCaX509.PublicKey.(*ecdsa.PublicKey)
	//fmt.Println(*pub1)
	fmt.Println("---------PAST DUE---------")
	fmt.Println("subcert: ", certByCaX509.NotAfter)
	fmt.Println("rootcert: ", rootCert.NotAfter)
	fmt.Println("--------------------------")
	_, err = primitives.VerifyCert(certByCaX509, rootCert)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

//签名
//func SignPayload(certPrivPath string, payload []byte) ([]byte, error) {
//
//	ee := primitives.NewEcdsaEncrypto("ecdsa")
//	//payload := []byte{1,2,3}
//
//	certPrivContent, err := ioutil.ReadFile(certPrivPath)
//	if err != nil {
//		return nil, err
//	}
//
//	pri, err := primitives.ParsePriKey(string(certPrivContent))
//	if err != nil {
//		return nil, err
//	}
//
//	//fmt.Println(pri)
//	sign, err := ee.Sign(payload, pri)
//
//	if err != nil {
//		return nil, err
//	}
//	return sign, nil
//}
//
////测试签名
//func VerifyPayload(certPath string, signedPayload []byte, originPayload []byte) (bool, error) {
//
//	certContent, err := ioutil.ReadFile(certPath)
//	if err != nil {
//		return false, err
//	}
//	cert, err := primitives.ParseCertificate(certContent)
//	if err != nil {
//		return false, err
//	}
//	pub := cert.PublicKey
//
//	return primitives.ECDSAVerify(pub, originPayload, signedPayload)
//}

//检查证书
func CheckCert(subCertPath, parentCertPath string) (bool, error) {
	subCertContent, err := ioutil.ReadFile(subCertPath)
	if err != nil {
		return false, err
	}
	parentCertContent, err := ioutil.ReadFile(parentCertPath)
	if err != nil {
		return false, err
	}

	parentCert, err := primitives.ParseCertificate(parentCertContent)
	if err != nil {
		return false, err
	}
	subCert, err := primitives.ParseCertificate(subCertContent)
	if err != nil {
		return false, err
	}
	return primitives.VerifyCert(subCert, parentCert)
}

//检查证书类型
func CheckCertType(certPath string) (certType string, err error) {
	certContent, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert, err := primitives.ParseCertificate(certContent)
	if err != nil {
		return "", err
	}
	for _, v := range cert.Extensions {
		if gmx509.CertTypeOID.Equal(v.Id) {
			return "Cert type is:" + string(gmx509.ParseCertType(v.Value).GetValue()), nil
		}
	}
	return "This certificate doesn't have type!", nil
}

//检查签名算法
func CheckAlgorithm(certPath string) (certType string, err error) {
	tmp := `
Cert is %v cert
Signature algorithm is: %v
`
	certContent, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert, err := primitives.ParseCertificate(certContent)
	if err != nil {
		return "", err
	}
	isGuomi := "guomi"
	algo := ""
	switch cert.SignatureAlgorithm {
	case gmx509.SM3WithSM2:
		algo = "SM2WithSM3"
	case gmx509.SHA1WithSM2:
		algo = "SM2WithSHA1"
	case gmx509.SHA512WithSM2:
		algo = "SM2WithSHA512"
	case gmx509.ECDSAWithSHA1:
		algo = "ECDSAWithSHA1"
		isGuomi = "non-guomi"
	case gmx509.ECDSAWithSHA256:
		algo = "ECDSAWithSHA256"
		isGuomi = "non-guomi"
	case gmx509.ECDSAWithSHA384:
		algo = "ECDSAWithSHA384"
		isGuomi = "non-guomi"
	default:
		algo = "Signature algorithm is not belong to ECDSA or SM"
		isGuomi = "non-guomi"
	}

	return fmt.Sprintf(tmp, isGuomi, algo), nil
}
