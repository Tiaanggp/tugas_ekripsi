package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
)

type Request struct {
    Text string `json:"text"`
    Type string `json:"type"`
}

type Response struct {
    Result    string `json:"result,omitempty"`
    PublicKey string `json:"publicKey,omitempty"`
    Error     string `json:"error,omitempty"`
}

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// Initialize RSA keys only once
func initKeys() error {
    var err error
    privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return fmt.Errorf("error generating RSA keys: %w", err)
    }
    publicKey = &privateKey.PublicKey
    return nil
}

// Handler for Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
    // Handle CORS
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

    // Handle OPTIONS request (CORS preflight)
    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusOK)
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Bad request", http.StatusBadRequest)
        return
    }

    if req.Type == "encrypt" {
        encryptedText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(req.Text), nil)
        if err != nil {
            json.NewEncoder(w).Encode(Response{Error: "Encryption failed"})
            return
        }
        json.NewEncoder(w).Encode(Response{Result: base64.StdEncoding.EncodeToString(encryptedText), PublicKey: base64.StdEncoding.EncodeToString(publicKey.N.Bytes())})
    } else if req.Type == "decrypt" {
        encryptedBytes, err := base64.StdEncoding.DecodeString(req.Text)
        if err != nil {
            json.NewEncoder(w).Encode(Response{Error: "Invalid base64 string"})
            return
        }
        decryptedText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedBytes, nil)
        if err != nil {
            json.NewEncoder(w).Encode(Response{Error: "Decryption failed"})
            return
        }
        json.NewEncoder(w).Encode(Response{Result: string(decryptedText)})
    } else {
        http.Error(w, "Invalid operation type", http.StatusBadRequest)
    }
}

// Entry point for the Vercel serverless function
func main() {
    if err := initKeys(); err != nil {
        fmt.Println(err)
        return
    }
    // Note: The server function is handled by Vercel, no need for ListenAndServe
}
