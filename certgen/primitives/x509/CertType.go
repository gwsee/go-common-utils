package x509

import (
	"bytes"
	"encoding/asn1"
)

type CertType int

const (
	ECert CertType = iota
	RCert
	SDKCert
	TCert
	ERCert
	UnknownCertType
)

//CertTtypeOID
var CertTypeOID asn1.ObjectIdentifier = []int{1, 2, 86, 1}

var certTypeList = [...][]byte{
	ECert:           []byte("hypechain_ecert"),
	RCert:           []byte("hyperchain_rcert"),
	SDKCert:         []byte("hyperchain_sdkcert"),
	TCert:           []byte("hyperchain_tcert"),
	ERCert:          []byte("hyperchain_ercert"),
	UnknownCertType: []byte("unknown cert type"),
}

func NewCertType(certType string) CertType {
	switch certType {
	case "ecert":
		return ECert
	case "rcert":
		return RCert
	case "sdkcert":
		return SDKCert
	case "tcert":
		return TCert
	case "ercert":
		return ERCert
	}
	return UnknownCertType
}

func ParseCertType(certType []byte) CertType {
	for i := range certTypeList {
		if bytes.Contains(certType, certTypeList[i]) {
			return CertType(i)
		}
	}
	return UnknownCertType
}

func (c CertType) GetValue() []byte {
	if c < 0 && c > UnknownCertType {
		return []byte("illegal type")
	}
	return certTypeList[c]
}

//func (c CertType) IsCA() bool {
//	return c == ECert
//}

func AssertCertType(expect CertType, certificate *Certificate) bool {
	for _, v := range certificate.Extensions {
		if CertTypeOID.Equal(v.Id) &&
			ParseCertType(v.Value) == expect {
			return true
		}
	}
	return false
}
