package main

import (
    "fmt"
    "net/http"
    "jwks-server/handlers"
    "jwks-server/keys"
)

func main() {
    km := keys.NewKeyManager()
    
    // Generate initial key
    km.GenerateKey(false)

    http.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler(km))
    http.HandleFunc("/auth", handlers.AuthHandler(km))

    fmt.Println("Server running on :8080")
    http.ListenAndServe(":8080", nil)
}