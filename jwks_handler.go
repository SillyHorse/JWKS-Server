package handlers

import (
    "encoding/base64"
    "encoding/json"
    "net/http"
    "jwks-server/keys"
)

type JWKSResponse struct {
    Keys []JWK `json:"keys"`
}

type JWK struct {
    Kid string `json:"kid"`
    Kty string `json:"kty"`
    Alg string `json:"alg"`
    Use string `json:"use"`
    N   string `json:"n"`
    E   string `json:"e"`
}

func JWKSHandler(km *keys.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        validKeys := km.GetValidKeys()
        response := JWKSResponse{Keys: make([]JWK, 0)}

        for _, key := range validKeys {
            n := base64.RawURLEncoding.EncodeToString(key.Public.N.Bytes())
            eBytes := []byte{byte(key.Public.E >> 16), byte(key.Public.E >> 8), byte(key.Public.E)}
            e := base64.RawURLEncoding.EncodeToString(eBytes)

            response.Keys = append(response.Keys, JWK{
                Kid: key.Kid,
                Kty: "RSA",
                Alg: "RS256",
                Use: "sig",
                N:   n,
                E:   e,
            })
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}