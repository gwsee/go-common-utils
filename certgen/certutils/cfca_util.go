package certutils

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"git.hyperchain.cn/dmlab/go-common-utils/certgen/guomi/sm2"
	gmx509 "git.hyperchain.cn/dmlab/go-common-utils/certgen/primitives/x509"
)

//1. 申请者名称 2.有效期截止时间（yyyyMMddHHmmss）3.证书类型（eg. tcert）4.P10
var bodyGuomi = `<?xml version="1.0" encoding="UTF-8"?>
<Request>
<Head>
<TxCode>1101</TxCode>
<Remark/>
<Locale/>
</Head>
<Body>
<CertType>2</CertType>
<CustomerType>1</CustomerType>
<UserName>hyperchain</UserName>
<UserNameInDn/>
<UserIdent/>
<IdentType>Z</IdentType>
<IdentNo>%s</IdentNo>
<KeyAlg>SM2</KeyAlg>
<KeyLength>256</KeyLength>
<BranchCode>678</BranchCode>
<Email/>
<PhoneNo/>
<Address/>
<Duration/>
<EndTime>%s</EndTime>
<AddEmailExt/>
<AddIdentNoExt/>
<SelfExtValue>%s</SelfExtValue>
<DomainName/>
<P10>%s</P10>
<P10Sub/>
<DeviceIdentifier/>
<DepartmentNameInCert/>
<OrganizationNameInCert/>
<Locality/>
<StateOrProvince/>
<Country/>
</Body>
</Request>`

//ApplyCFCACert Apply for a ra certificate
func ApplyCFCACert(name string, gmPriv *sm2.PrivateKey, certType gmx509.CertType, endTime time.Time, url string) ([]byte, error) {
	var lineWidth = 73
	p10, err := p10RequestSM2(gmPriv)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf(bodyGuomi, name, endTime.Format("20060102150405"), string(certType.GetValue()), p10)
	raw, err := httpDo(query, url)
	if err != nil {
		return nil, err
	}
	certByte := []byte(raw)
	length := len(certByte)
	lineNum := length / lineWidth
	var isRemaining = 0
	if length%lineWidth != 0 {
		isRemaining = 1
	}
	target := make([]byte, length+lineNum+isRemaining)
	for i, line := 0, 0; i < length; i++ {
		if i%lineWidth == 0 {
			target[i+line] = '\n'
			line++
		}
		target[i+line] = certByte[i]
	}
	target = append([]byte("-----BEGIN CERTIFICATE-----"), target...)
	target = append(target, []byte("\n-----END CERTIFICATE-----")...)
	return target, nil
}

func httpDo(CSRbody, url string) (string, error) {
	//解析返回的数据
	type RPhead struct {
		TxCode        string `xml:"TxCode"`
		TxTime        string `xml:"TxTime"`
		ResultCode    string `xml:"ResultCode"`
		ResultMessage string `xml:"ResultMessage"`
	}
	type RPbody struct {
		Dn                      string `xml:"Dn"`
		SequenceNo              string `xml:"SequenceNo"`
		SerialNo                string `xml:"SerialNo"`
		StartTime               string `xml:"StartTime"`
		EndTime                 string `xml:"EndTime"`
		SignatureCert           string `xml:"SignatureCert"`
		EncryptionCert          string `xml:"EncryptionCert"`
		EncryptionPrivateKey    string `xml:"EncryptionPrivateKey"`
		SignatureCertSub        string `xml:"SignatureCertSub"`
		EncryptionCertSub       string `xml:"EncryptionCertSub"`
		EncryptionPrivateKeySub string `xml:"EncryptionPrivateKeySub"`
	}
	var RP struct {
		Head RPhead `xml:"Head"`
		Body RPbody `xml:"Body"`
	}

	req, err := http.NewRequest("POST", url,
		strings.NewReader(CSRbody))
	if err != nil {
		return "", err
	}
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "CFCARAClient 3.5")
	req.Header.Add("Accept", "test/xml")
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Add("Host", "40.125.214.115:8080")
	req.Header.Del("Accept-Encoding")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	err = xml.Unmarshal(body, &RP)
	if err != nil {
		return "", err
	}
	return RP.Body.SignatureCert, nil
}

func p10RequestSM2(GmPrivateKey *sm2.PrivateKey) (string, error) {
	template := gmx509.CertificateRequest{
		SignatureAlgorithm: gmx509.SM3WithSM2,
	}
	derBytes, err := gmx509.CreateCertificateRequest(rand.Reader, &template, GmPrivateKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "P10",
		Bytes: derBytes,
	}
	buf := make([]byte, 0)
	io := bytes.NewBuffer(buf)
	if pem.Encode(io, block) != nil {
		return "", err
	}
	result := io.Bytes()
	result = bytes.TrimPrefix(result, []byte("-----BEGIN P10-----\n"))
	result = bytes.TrimSuffix(result, []byte("-----END P10-----\n"))
	result = bytes.Join(bytes.Split(result, []byte{'\n'}), nil)
	return string(result), nil
}

//Verify 验证证书的合法性
func Verify(DN string) (bool, error) {
	request := `
<Request>
<Head>
<TxCode>7102</TxCode>
<Remark/>
<Locale/>
</Head>
<Body>
<SerialNo/>
<Dn>%s</Dn>
</Body>
</Request>
`
	type RPbody struct {
		Dn           string `xml:"Dn"`
		SequenceNo   string `xml:"SequenceNo"`
		SerialNo     string `xml:"SerialNo"`
		CertStatus   string `xml:"CertStatus"`
		Duration     string `xml:"Duration"`
		ApplyTime    string `xml:"ApplyTime"`
		SendcodeTime string `xml:"SendcodeTime"`
		StartTime    string `xml:"StartTime"`
		EndTime      string `xml:"EndTime"`
		BranchCode   string `xml:"BranchCode"`
		KeyAlg       string `xml:"keyAlg"`
		KeyLength    string `xml:"KeyLength"`
		DomainName   string `xml:"DomainName"`
		Email        string `xml:"Email"`
	}
	type RPhead struct {
		TxCode        string `xml:"TxCode"`
		TxTime        string `xml:"TxTime"`
		ResultCode    string `xml:"ResultCode"`
		ResultMessage string `xml:"ResultMessage"`
	}
	var RP struct {
		Head RPhead `xml:"Head"`
		Body RPbody `xml:"Body"`
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "http://40.125.214.115:8080/raWeb/CSHttpServlet",
		strings.NewReader(fmt.Sprintf(request, DN)))
	if err != nil {
		fmt.Println(err.Error())
	}
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "CFCARAClient 3.5")
	req.Header.Add("Accept", "test/xml")
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Add("Host", "40.125.214.115:8080")
	req.Header.Del("Accept-Encoding")

	resp, err := client.Do(req)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if xml.Unmarshal(body, &RP) != nil {
		return false, err
	}

	if RP.Head.ResultCode == "0000" {
		switch RP.Body.CertStatus {
		case "3":
			return false, errors.New("证书未下载")
		case "6":
			return false, errors.New("证书已经被吊销")
		case "5":
			return false, errors.New("证书已经被冻结")
		case "4":
			return true, nil
		default:
			return false, errors.New("未知的证书状态")
		}
	} else if RP.Head.ResultMessage == "证书不存在" {
		return false, errors.New("证书不存在")
	}

	return false, errors.New("未知的证书状态")
}

//CN=051@hyperchain@Zclientname@10,OU=Individual-2,OU=Local RA,O=CFCA TEST CA,C=CN
func GetDN(cert *gmx509.Certificate) string {
	start := "CN=" + cert.Subject.CommonName + ","

	ou := make([]string, len(cert.Subject.OrganizationalUnit))
	for i := range cert.Subject.OrganizationalUnit {
		ou[i] = "OU=" + cert.Subject.OrganizationalUnit[i] + ","
	}
	sort.Strings(ou)
	if len(ou) != 0 {
		start += strings.Join(ou, "")
	}

	o := make([]string, len(cert.Subject.Organization))
	for i := range cert.Subject.Organization {
		o[i] = "O=" + cert.Subject.Organization[i] + ","
	}
	sort.Strings(o)
	if len(o) != 0 {
		start += strings.Join(o, "")
	}

	c := make([]string, len(cert.Subject.Country))
	for i := range cert.Subject.Country {
		c[i] = "C=" + cert.Subject.Country[i] + ","
	}
	sort.Strings(c)
	if len(c) != 0 {
		start += strings.Join(c, "")
	}

	return strings.Trim(start, ",")
}
