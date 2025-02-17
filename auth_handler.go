package handlers

import (
	"encoding/json"
	"net/http"

	"jwks-server/keys"
	"jwks-server/utils"

	"github.com/golang-jwt/jwt/v5"
)

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	expiredRequested := r.URL.Query().Get("expired") == "true"
	signingKey := keys.GetSigningKey(expiredRequested)

	if signingKey.PrivateKey == nil {
		http.Error(w, "No valid keys available", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, utils.Claims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(signingKey.Expiry),
		},
	})

	token.Header["kid"] = signingKey.Kid
	signedToken, err := token.SignedString(signingKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}
