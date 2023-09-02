package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

func isCertIn(certs []x509.Certificate, pCert *x509.Certificate) (result bool) {
	result = false

	for _, cmpCert := range certs {
		if cmpCert.Equal(pCert) {
			result = true
			return
		}
	}

	return
}

func addCert(pCmdline *cmdline, pCerts *[]x509.Certificate, pCert *x509.Certificate) {
	if (pCert.IsCA || !pCmdline.caOnly) && !isCertIn(*pCerts, pCert) {
		*pCerts = append(*pCerts, *pCert)
	}
}

func downloadCertificate(url string) (pOutCert *x509.Certificate, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	pOutCert, err = x509.ParseCertificate(body)
	return
}

func downloadIntermediateCerts(pCertReg *map[string](*x509.Certificate), pCertUrls []string) (err error) {
	pUrls := pCertUrls

	for len(pUrls) > 0 {
		currentUrl := pUrls[0]
		_, ok := (*pCertReg)[currentUrl]
		if !ok {
			currentCert, cerr := downloadCertificate(currentUrl)
			if cerr != nil {
				err = errors.Join(
					err,
					cerr)
			} else {
				(*pCertReg)[currentUrl] = currentCert
				for _, nextURL := range currentCert.IssuingCertificateURL {
					pUrls = append(pUrls, nextURL)
				}
			}
		}
		pUrls = pUrls[1:]
	}

	return
}

func getIntermediatesCertPool(pCertReg *map[string](*x509.Certificate), pCertificate *x509.Certificate) (pCertPool *x509.CertPool, err error) {
	pIntermediateCertURLs := pCertificate.IssuingCertificateURL
	pCertPool = x509.NewCertPool()

	cerr := downloadIntermediateCerts(pCertReg, pIntermediateCertURLs)
	if cerr != nil {
		err = errors.Join(
			err,
			cerr)
	}

	for _, pCert := range *pCertReg {
		pCertPool.AddCert(pCert)
	}

	return
}

func perform(pCmdline *cmdline) (err error) {
	data, err := os.ReadFile(pCmdline.inFile)
	if err != nil {
		return
	}

	var outCerts []x509.Certificate
	certReg := make(map[string](*x509.Certificate))
	for {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			certificate, cerr := x509.ParseCertificate(block.Bytes)
			if cerr != nil {
				err = errors.Join(
					err,
					cerr)
				continue
			}
			pCertPool, cerr := getIntermediatesCertPool(&certReg, certificate)
			if cerr != nil {
				err = errors.Join(
					err,
					cerr)
			}
			certChains, cerr := certificate.Verify(x509.VerifyOptions{
				Intermediates: pCertPool})
			if cerr != nil {
				err = errors.Join(
					err,
					cerr)
				continue
			}
			for _, certChain := range certChains {
				for _, pCert := range certChain {
					addCert(pCmdline, &outCerts, pCert)
				}
			}
		default:
			err = errors.Join(
				err,
				errors.New(fmt.Sprintf("pem type %s not supported.\n", block.Type)))
		}
	}

	outFile, cerr := os.Create(pCmdline.outFile)
	if cerr != nil {
		err = errors.Join(err, cerr)
		return
	}
	defer outFile.Close()

	for _, outCert := range outCerts {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: outCert.Raw,
		}
		if cerr := pem.Encode(outFile, &block); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}

	return
}
