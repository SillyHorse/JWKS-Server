package handlers

import (
    "encoding/json"
    "net/http"
    "jwks-server/keys"
    "time"
    "github.com/golang-jwt/jwt/v5"
)

func AuthHandler(km *keys.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        expired := r.URL.Query().Get("expired") == "true"
        key := km.GenerateKey(expired)

        claims := jwt.MapClaims{
            "sub":  "1234567890",
            "name": "John Doe",
            "iat":  time.Now().Unix(),
            "exp":  key.Expiry.Unix(),
        }

        token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
        token.Header["kid"] = key.Kid
        
        signedToken, _ := token.SignedString(key.Private)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "token": signedToken,
        })
    }
}