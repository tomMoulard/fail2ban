package certchain

import (
	"crypto/x509"
	"fmt"
)

func VerifyForCodeSigning(certs []*x509.Certificate, failWithoutFullChain bool) error {
	var leaf *x509.Certificate
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	certs = Sort(certs)

	for i, c := range certs {
		switch i {
		case 0, len(certs) - 1:
			if c.IsCA {
				roots.AddCert(c)
			} else {
				leaf = c
			}
		default:
			intermediates.AddCert(c)
		}
	}

	if leaf == nil {
		return fmt.Errorf("no leaf ceritificate found")
	}

	if len(certs) == 1 {
		if failWithoutFullChain {
			return fmt.Errorf("verification failed: full certificate chain not present (%d certificates found)", len(certs))
		}
		// no chain to verify with
		return nil
	}

	// verify with the chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning, // we know this is a signing cert..
		},
	}

	// ignore "devid_execute" and "devid_kernel" critical extensions
	temp := leaf.UnhandledCriticalExtensions[:0]
	for _, ex := range leaf.UnhandledCriticalExtensions {
		switch ex.String() {
		case "1.2.840.113635.100.6.1.13": // devid_execute
			continue
		case "1.2.840.113635.100.6.1.18": // devid_kernel
			continue
		default:
			temp = append(temp, ex)
		}
	}
	leaf.UnhandledCriticalExtensions = temp

	if len(leaf.UnhandledCriticalExtensions) > 0 {
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate chain: %w", err)
	}
	return nil
}
