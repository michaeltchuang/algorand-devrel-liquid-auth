package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

type VerifyRequest struct {
	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature"`
	Message   []byte `json:"message"`
}

type VerifyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

func main() {
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/health", healthHandler)

	port := ":3002"
	fmt.Printf("Starting Falcon verification server on http://localhost%s\n", port)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /verify  - Verify Falcon signature")
	fmt.Println("  GET  /health  - Health check")
	fmt.Println()

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req VerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(req.PublicKey) == 0 {
		resp := VerifyResponse{Valid: false, Error: "Missing publicKey"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	if len(req.Signature) == 0 {
		resp := VerifyResponse{Valid: false, Error: "Missing signature"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	if len(req.Message) == 0 {
		resp := VerifyResponse{Valid: false, Error: "Missing message"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Convert to Falcon public key type
	var publicKey falcongo.PublicKey
	if len(req.PublicKey) != len(publicKey) {
		resp := VerifyResponse{
			Valid: false,
			Error: fmt.Sprintf("Invalid public key length: expected %d, got %d", len(publicKey), len(req.PublicKey)),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	copy(publicKey[:], req.PublicKey)

	// Verify the signature using falcongo
	// CompressedSignature is just []byte, so use req.Signature directly
	// Verify returns error if invalid, nil if valid
	verifyErr := falcongo.Verify(req.Message, req.Signature, publicKey)
	
	resp := VerifyResponse{
		Valid: verifyErr == nil,
	}
	if verifyErr != nil {
		resp.Error = fmt.Sprintf("Verification failed: %v", verifyErr)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}


