package qodercn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// The COSY request signature is what the official Qoder CN client produces via
// the bundled qoder_auth_wasm module (`qodercontext_prepareRequest`). The plain
// bearer-token path (/model/v1/chat/completions) rejects these credentials with
// 401; only the signed /algo/.../agent_chat_generation transport accepts them.
//
// Scheme (recovered alongside github.com/…/qoder2api and verified live against
// gateway.qoder.com.cn):
//
//	tempKey   = 16 hex characters (used as an AES-128 key)
//	cosyKey   = base64(RSA_PKCS1v15(tempKey, serverPublicKey))
//	info      = base64(AES-128-CBC(identityJSON, key=tempKey, iv=tempKey))
//	payloadB64= base64({cosyVersion, ideVersion, info, requestId, version})
//	signature = md5(payloadB64\n cosyKey\n cosyDate\n body\n path)
//	Authorization: Bearer COSY.<payloadB64>.<signature>
//
// `body` is the request body after the custom base64 variant (CosyEncode), which
// is what the `Encode=1` query parameter asks the gateway to expect.

const (
	// cosyStdAlphabet is the standard base64 alphabet.
	cosyStdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// cosyCustomAlphabet is the permuted alphabet Qoder expects for Encode=1 bodies.
	cosyCustomAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	// cosyCustomPad replaces the standard '=' padding character.
	cosyCustomPad = '$'

	// cosyServerPublicKeyPEM is the RSA public key the official CN client uses to
	// wrap the per-request AES key. It is embedded in qoder_auth_wasm.
	cosyServerPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`
)

var (
	cosyPublicKeyOnce sync.Once
	cosyPublicKey     *rsa.PublicKey
	cosyPublicKeyErr  error
)

// CosyIdentity carries the account fields the signature envelope encrypts. All
// of Name/UID/AID must be non-empty: the gateway derives the tenant from them
// and silently drops requests whose identity block is blank.
type CosyIdentity struct {
	Name             string
	AID              string
	UID              string
	YXUID            string
	OrganizationID   string
	OrganizationName string
	UserType         string
	// SecurityOAuth is the device access token (the `dt-…` bearer).
	SecurityOAuth string
	// RefreshToken is included so the gateway can rotate it server-side.
	RefreshToken string
}

// CosySession is the per-request signing material. A fresh session is cheap; a
// new tempKey/cosyKey pair is generated for every request, matching the client.
type CosySession struct {
	CosyKey      string
	Info         string
	MachineID    string
	MachineToken string
	MachineType  string
}

// NewCosySession derives a fresh signing session for one identity.
func NewCosySession(identity CosyIdentity) (*CosySession, error) {
	tempKey := []byte(randomHexChars(16))
	cosyKey, err := rsaEncryptBase64(tempKey)
	if err != nil {
		return nil, err
	}
	info, err := cosyEncryptInfo(identity, tempKey)
	if err != nil {
		return nil, err
	}
	return &CosySession{
		CosyKey:      cosyKey,
		Info:         info,
		MachineID:    uuid.NewString(),
		MachineToken: randomCosyMachineToken(),
		MachineType:  randomHexChars(18),
	}, nil
}

// PayloadB64 builds the base64 JSON envelope bound into the Authorization header.
func (s *CosySession) PayloadB64(cosyVersion string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("qoder-cn: cosy session is nil")
	}
	payload := struct {
		CosyVersion string `json:"cosyVersion"`
		IdeVersion  string `json:"ideVersion"`
		Info        string `json:"info"`
		RequestID   string `json:"requestId"`
		Version     string `json:"version"`
	}{
		CosyVersion: cosyVersion,
		Info:        s.Info,
		RequestID:   uuid.NewString(),
		Version:     "v1",
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("qoder-cn: encode payload envelope: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// CosySign computes the request signature over the newline-joined components.
// MD5 is mandated by the Qoder COSY protocol: the gateway recomputes and compares
// the same digest. It is a transport checksum, not a security boundary, so a
// stronger primitive cannot be substituted.
func CosySign(payloadB64, cosyKey, cosyDate, body, path string) string {
	joined := payloadB64 + "\n" + cosyKey + "\n" + cosyDate + "\n" + body + "\n" + path
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5
	sum := md5.Sum([]byte(joined)) //nolint:gosec // #nosec G401 -- protocol-defined COSY signature requires MD5.
	return hex.EncodeToString(sum[:])
}

// CosyEncode applies the custom base64 variant the Encode=1 body uses: the
// standard base64 is rotated by a third and the alphabet permuted.
func CosyEncode(plaintext []byte) string {
	std := base64.StdEncoding.EncodeToString(plaintext)
	n := len(std)
	if n == 0 {
		return ""
	}
	a := n / 3
	rearranged := std[n-a:] + std[a:n-a] + std[:a]

	out := make([]byte, n)
	for i := 0; i < n; i++ {
		c := rearranged[i]
		if c == '=' {
			out[i] = cosyCustomPad
			continue
		}
		idx := strings.IndexByte(cosyStdAlphabet, c)
		if idx < 0 {
			out[i] = c
			continue
		}
		out[i] = cosyCustomAlphabet[idx]
	}
	return string(out)
}

// cosyEncryptInfo AES-128-CBC encrypts the identity JSON with key=iv=tempKey.
func cosyEncryptInfo(identity CosyIdentity, key []byte) (string, error) {
	payload := map[string]string{
		"name":                 identity.Name,
		"aid":                  identity.AID,
		"uid":                  identity.UID,
		"yx_uid":               identity.YXUID,
		"organization_id":      identity.OrganizationID,
		"organization_name":    identity.OrganizationName,
		"user_type":            identity.UserType,
		"security_oauth_token": identity.SecurityOAuth,
		"refresh_token":        identity.RefreshToken,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("qoder-cn: encode identity: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("qoder-cn: build identity cipher: %w", err)
	}
	plain = cosyPKCS5Pad(plain, block.BlockSize())
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out), nil
}

// rsaEncryptBase64 wraps the AES key with the embedded server public key.
func rsaEncryptBase64(plain []byte) (string, error) {
	pub, err := cosyServerPublicKey()
	if err != nil {
		return "", err
	}
	out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plain)
	if err != nil {
		return "", fmt.Errorf("qoder-cn: wrap cosy key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func cosyServerPublicKey() (*rsa.PublicKey, error) {
	cosyPublicKeyOnce.Do(func() {
		block, _ := pem.Decode([]byte(cosyServerPublicKeyPEM))
		if block == nil {
			cosyPublicKeyErr = fmt.Errorf("qoder-cn: invalid embedded server public key")
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			cosyPublicKeyErr = fmt.Errorf("qoder-cn: parse server public key: %w", err)
			return
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			cosyPublicKeyErr = fmt.Errorf("qoder-cn: embedded key is not RSA")
			return
		}
		cosyPublicKey = key
	})
	return cosyPublicKey, cosyPublicKeyErr
}

// randomHexChars returns n lowercase hex characters (so []byte(result) is n bytes).
func randomHexChars(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(buf)[:n]
}

// randomCosyMachineToken mirrors the official client's opaque machine token.
func randomCosyMachineToken() string {
	raw := uuid.NewString() + uuid.NewString()
	if len(raw) > 50 {
		raw = raw[:50]
	}
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func cosyPKCS5Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}
	padding := blockSize - len(data)%blockSize
	out := make([]byte, 0, len(data)+padding)
	out = append(out, data...)
	for i := 0; i < padding; i++ {
		out = append(out, byte(padding))
	}
	return out
}
