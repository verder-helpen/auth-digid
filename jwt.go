package main

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwt"
)

// Construct an attribute JWT signed and encrypted with given keys
func buildAttributeJWT(attributes map[string]string, sessionUrl string, signKey *rsa.PrivateKey, encryptionKey *rsa.PublicKey) ([]byte, error) {
	token := jwt.New()
	token.Set(jwt.SubjectKey, "id-contact-attributes")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*5))
	token.Set("status", "success")
	token.Set("attributes", attributes)
	token.Set("session_url", sessionUrl)
	signed, err := jwt.Sign(token, jwa.RS256, signKey)
	if err != nil {
		return nil, err
	}
	outer := make(map[string]string)
	outer["njwt"] = string(signed)
	outerJSON, err := json.Marshal(outer)
	if err != nil {
		return nil, err
	}
	return jwe.Encrypt(outerJSON, jwa.RSA_OAEP, encryptionKey, jwa.A128CBC_HS256, jwa.NoCompress)
}
