package keys

import (
    "crypto/rand"
    "crypto/rsa"
    "sync"
    "time"
    "github.com/google/uuid"
)

type Key struct {
    Kid     string
    Expiry  time.Time
    Private *rsa.PrivateKey
    Public  *rsa.PublicKey
}

type KeyManager struct {
    keys sync.Map
}

func NewKeyManager() *KeyManager {
    return &KeyManager{}
}

func (km *KeyManager) GenerateKey(expired bool) *Key {
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    expiry := time.Now().Add(1 * time.Hour)
    if expired {
        expiry = time.Now().Add(-1 * time.Hour)
    }

    key := &Key{
        Kid:     uuid.New().String(),
        Expiry:  expiry,
        Private: privateKey,
        Public:  publicKey,
    }

    km.keys.Store(key.Kid, key)
    return key
}

func (km *KeyManager) GetValidKeys() []*Key {
    var validKeys []*Key
    km.keys.Range(func(kid, value interface{}) bool {
        key := value.(*Key)
        if key.Expiry.After(time.Now()) {
            validKeys = append(validKeys, key)
        }
        return true
    })
    return validKeys
}