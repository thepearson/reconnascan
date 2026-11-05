package analyzer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestEvaluateTLSGrade(t *testing.T) {
	t.Run("A+ Modern TLS 1.3 with CT", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:              true,
			NegotiatedVersion:   "TLS 1.3",
			SupportedVersions:   []string{"TLS 1.2", "TLS 1.3"},
			CipherSuite:         "TLS_AES_128_GCM_SHA256",
			KeyAlgorithm:        "ECDSA P-256 (256-bit)",
			ChainValid:          true,
			DaysRemaining:       75,
			HasCertTransparency: true,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "A+" {
			t.Errorf("expected Grade A+, got %s (warnings: %v)", info.Grade, info.GradeWarnings)
		}
	})

	t.Run("B when deprecated TLS 1.0/1.1 supported", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:             true,
			NegotiatedVersion:  "TLS 1.3",
			SupportedVersions:  []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"},
			DeprecatedVersions: []string{"TLS 1.0", "TLS 1.1"},
			CipherSuite:        "TLS_AES_128_GCM_SHA256",
			KeyAlgorithm:       "RSA 2048-bit",
			ChainValid:         true,
			DaysRemaining:      60,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "B" {
			t.Errorf("expected Grade B when deprecated TLS 1.0/1.1 enabled, got %s", info.Grade)
		}
	})

	t.Run("F when certificate expired or chain invalid", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:            true,
			NegotiatedVersion: "TLS 1.3",
			SupportedVersions: []string{"TLS 1.3"},
			CipherSuite:       "TLS_AES_128_GCM_SHA256",
			ChainValid:        false,
			ChainError:        "x509: certificate signed by unknown authority",
			DaysRemaining:     -5,
		}
		EvaluateTLSGrade(&info, false)
		if info.Grade != "F" {
			t.Errorf("expected Grade F for expired/untrusted cert, got %s", info.Grade)
		}
	})

	t.Run("Enterprise TLS Interception warning is recorded", func(t *testing.T) {
		info := TLSInfo{
			HasTLS:               true,
			NegotiatedVersion:    "TLS 1.3",
			SupportedVersions:    []string{"TLS 1.3"},
			CipherSuite:          "TLS_AES_128_GCM_SHA256",
			ChainValid:           true,
			DaysRemaining:        60,
			InterceptionDetected: true,
			InterceptionVendor:   "Netskope",
		}
		EvaluateTLSGrade(&info, false)
		foundWarning := false
		for _, w := range info.GradeWarnings {
			if strings.Contains(w, "Enterprise TLS Interception active (Netskope)") {
				foundWarning = true
				break
			}
		}
		if !foundWarning {
			t.Errorf("expected interception warning in GradeWarnings, got: %v", info.GradeWarnings)
		}
	})
}

func TestDetectTLSInterception(t *testing.T) {
	t.Run("Netskope detection on leaf issuer", func(t *testing.T) {
		cert := &x509.Certificate{
			Issuer: pkix.Name{
				Organization: []string{"Netskope Inc"},
				CommonName:   "ca.goskope.com",
			},
		}
		detected, vendor, details := DetectTLSInterception([]*x509.Certificate{cert})
		if !detected || vendor != "Netskope" {
			t.Fatalf("expected Netskope detected, got detected=%v vendor=%s details=%s", detected, vendor, details)
		}
	})

	t.Run("Zscaler detection in intermediate CA", func(t *testing.T) {
		leaf := &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "example.com",
			},
		}
		ca := &x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"Zscaler Inc."},
				CommonName:   "Zscaler Intermediate Root CA",
			},
		}
		detected, vendor, details := DetectTLSInterception([]*x509.Certificate{leaf, ca})
		if !detected || vendor != "Zscaler" {
			t.Fatalf("expected Zscaler detected, got detected=%v vendor=%s details=%s", detected, vendor, details)
		}
	})

	t.Run("Palo Alto Networks detection", func(t *testing.T) {
		cert := &x509.Certificate{
			Issuer: pkix.Name{
				Organization: []string{"Palo Alto Networks"},
				CommonName:   "GlobalProtect Decryption CA",
			},
		}
		detected, vendor, _ := DetectTLSInterception([]*x509.Certificate{cert})
		if !detected || vendor != "Palo Alto Networks" {
			t.Fatalf("expected Palo Alto Networks, got %v (%s)", detected, vendor)
		}
	})

	t.Run("Normal public Web PKI CA not flagged as interception", func(t *testing.T) {
		cert := &x509.Certificate{
			Issuer: pkix.Name{
				Organization: []string{"Let's Encrypt"},
				CommonName:   "R3",
			},
		}
		detected, vendor, details := DetectTLSInterception([]*x509.Certificate{cert})
		if detected {
			t.Fatalf("normal Web PKI CA should not be flagged as interception, got vendor=%s details=%s", vendor, details)
		}
	})
}

func TestParseCrtShCertJSON(t *testing.T) {
	// Sample crt.sh JSON with an expired certificate and an active certificate
	future := time.Now().Add(90 * 24 * time.Hour).Format("2006-01-02T15:04:05")
	past := time.Now().Add(-10 * 24 * time.Hour).Format("2006-01-02T15:04:05")
	ancientPast := time.Now().Add(-400 * 24 * time.Hour).Format("2006-01-02T15:04:05")

	jsonBlob := `[
		{
			"issuer_ca_id": 16418,
			"issuer_name": "C=US, O=Let's Encrypt, CN=R3",
			"common_name": "example.com",
			"name_value": "example.com\nwww.example.com\napi.example.com",
			"id": 111111,
			"entry_timestamp": "` + ancientPast + `",
			"not_before": "` + ancientPast + `",
			"not_after": "` + past + `",
			"serial_number": "03deadbeef"
		},
		{
			"issuer_ca_id": 180753,
			"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
			"common_name": "example.com",
			"name_value": "example.com\nwww.example.com\ncdn.example.com",
			"id": 222222,
			"entry_timestamp": "` + past + `",
			"not_before": "` + past + `",
			"not_after": "` + future + `",
			"serial_number": "04cafebabe"
		}
	]`

	cert, err := ParseCrtShCertJSON([]byte(jsonBlob), "example.com")
	if err != nil {
		t.Fatalf("ParseCrtShCertJSON error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil CTCertificate")
	}

	if cert.IssuerOrg != "DigiCert Inc" {
		t.Errorf("expected IssuerOrg 'DigiCert Inc', got '%s'", cert.IssuerOrg)
	}
	if cert.SerialNumber != "04CAFEBABE" {
		t.Errorf("expected SerialNumber '04CAFEBABE', got '%s'", cert.SerialNumber)
	}
	if cert.DaysRemaining <= 0 {
		t.Errorf("expected DaysRemaining > 0 for active cert, got %d", cert.DaysRemaining)
	}
	if len(cert.SANDomains) != 3 {
		t.Errorf("expected 3 SANs, got %v", cert.SANDomains)
	}
}

func TestParseCertSpotterCertJSON(t *testing.T) {
	future := time.Now().Add(60 * 24 * time.Hour).Format(time.RFC3339)
	past := time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339)

	jsonBlob := `[
		{
			"id": "cert123",
			"dns_names": ["example.org", "www.example.org"],
			"not_before": "` + past + `",
			"not_after": "` + future + `",
			"issuer": {
				"name": "C=US, O=Let's Encrypt, CN=E1"
			}
		}
	]`

	cert, err := ParseCertSpotterCertJSON([]byte(jsonBlob), "example.org")
	if err != nil {
		t.Fatalf("ParseCertSpotterCertJSON error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil CTCertificate")
	}
	if cert.IssuerOrg != "Let's Encrypt" {
		t.Errorf("expected IssuerOrg 'Let's Encrypt', got '%s'", cert.IssuerOrg)
	}
	if cert.DaysRemaining <= 0 {
		t.Errorf("expected DaysRemaining > 0, got %d", cert.DaysRemaining)
	}
	if len(cert.SANDomains) != 2 {
		t.Errorf("expected 2 SAN domains, got %v", cert.SANDomains)
	}
}
