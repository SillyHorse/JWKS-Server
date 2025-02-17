package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"jwks-server/keys"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func GetJWKSHandler(w http.ResponseWriter, r *http.Request) {
	var jwks JWKS
	for _, key := range keys.GetUnexpiredKeys() {
		jwks.Keys = append(jwks.Keys, JWK{
			Kid: key.Kid,
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:   "AQAB",
			Alg: "RS256",
			Use: "sig",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
