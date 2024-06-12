package domains

import (
	"crypto/tls"
	"errors"
)

func Get(domain string) (DomainSettings, error) {
	val, ok := DomainsMap.Load(domain)
	if !ok {
		return DomainSettings{}, errors.New("domain not found")
	}
	return val.(DomainSettings), nil
}

func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {

	domainVal, ok := DomainsMap.Load(clientHello.ServerName)
	if ok {
		tempDomain := domainVal.(DomainSettings)
		return &tempDomain.DomainCertificates, nil
	}
	return nil, nil
}
