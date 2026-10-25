package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "p2px/1"

// keys holds everything derived from the shared secret. Both peers derive the
// same values, so the secret is the only thing that ever has to be shared.
type keys struct {
	topic     string             // ntfy topic used for signaling
	aead      cipher.AEAD        // encrypts and authenticates signaling messages
	serverKey ed25519.PrivateKey // TLS identity of the exit node (B)
	clientKey ed25519.PrivateKey // TLS identity of the client (A)

	// Stable across restarts, so a restarted peer can tell the other side at
	// once that the old connection is gone (QUIC stateless reset).
	serverReset, clientReset *quic.StatelessResetKey
}

func derive(secret, label string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(label))
	return m.Sum(nil)
}

func newKeys(secret string) (*keys, error) {
	if len(secret) < 16 {
		return nil, errors.New("key is missing or too short; generate one with: p2proxy genkey")
	}
	block, err := aes.NewCipher(derive(secret, "signal-aead"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &keys{
		topic:       "p2px_" + hex.EncodeToString(derive(secret, "signal-topic")[:20]),
		aead:        aead,
		serverKey:   ed25519.NewKeyFromSeed(derive(secret, "server-identity")),
		clientKey:   ed25519.NewKeyFromSeed(derive(secret, "client-identity")),
		serverReset: (*quic.StatelessResetKey)(derive(secret, "server-reset")),
		clientReset: (*quic.StatelessResetKey)(derive(secret, "client-reset")),
	}, nil
}

func genKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (k *keys) seal(plain []byte) string {
	nonce := make([]byte, k.aead.NonceSize())
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plain, nil))
}

func (k *keys) open(msg string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(msg))
	if err != nil {
		return nil, err
	}
	ns := k.aead.NonceSize()
	if len(b) < ns {
		return nil, errors.New("short message")
	}
	return k.aead.Open(nil, b[:ns], b[ns:], nil)
}

func certFor(priv ed25519.PrivateKey) tls.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// pinPeer accepts the peer only if its certificate carries the public key we
// derived from the shared secret. TLS itself proves the peer holds the
// matching private key.
func pinPeer(want ed25519.PrivateKey) func([][]byte, [][]*x509.Certificate) error {
	pub := want.Public().(ed25519.PublicKey)
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("peer sent no certificate")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		got, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !got.Equal(pub) {
			return errors.New("peer is not using the same key")
		}
		return nil
	}
}

func (k *keys) serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{certFor(k.serverKey)},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinPeer(k.clientKey),
		NextProtos:            []string{alpn},
	}
}

func (k *keys) clientTLS() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certFor(k.clientKey)},
		// Chain verification is replaced by key pinning in VerifyPeerCertificate.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinPeer(k.serverKey),
		NextProtos:            []string{alpn},
		ServerName:            "p2proxy",
	}
}
