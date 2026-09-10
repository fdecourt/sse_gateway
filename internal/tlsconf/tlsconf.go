package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Params regroupe les paramètres standard pour construire un *tls.Config sécurisé.
type Params struct {
	CertFile           string
	KeyFile            string
	CAFile             string
	InsecureSkipVerify bool
	ServerName         string
}

// Build construit un *tls.Config conforme aux exigences de sécurité (TLS 1.3 minimum).
func Build(p Params) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: p.InsecureSkipVerify,
		ServerName:         p.ServerName,
	}

	if p.CAFile != "" {
		caData, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, fmt.Errorf("lecture du fichier CA TLS échouée (%s): %w", p.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("aucun certificat valide trouvé dans le fichier CA: %s", p.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	if p.CertFile != "" && p.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("chargement du certificat client/clé TLS échoué: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
