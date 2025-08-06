package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"fmt"

	"github.com/smartcontractkit/tdh2/go/tdh2/lib/group/nist"
	tdh2 "github.com/smartcontractkit/tdh2/go/tdh2/tdh2"
)

// newStream returns a fresh random stream for use with TDH2 operations.
func newStream() cipher.Stream {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(fmt.Errorf("NewCipher: %w", err))
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := cryptorand.Read(iv); err != nil {
		panic(fmt.Errorf("Read: %w", err))
	}
	return cipher.NewCTR(block, iv)
}

func main() {
	// server generates keys and distributes shares to n nodes with threshold k
	group := nist.NewP256()
	k, n := 3, 5
	_, pk, shares, err := tdh2.GenerateKeys(group, nil, k, n, newStream())
	if err != nil {
		panic(fmt.Errorf("generate keys: %w", err))
	}

	// client encrypts a message using the public key and produces a proof
	msg := []byte("hello threshold proof messages!!")
	label := []byte("label for threshold demo proof!!")
	ctxt, err := tdh2.Encrypt(pk, msg, label, newStream())
	if err != nil {
		panic(fmt.Errorf("encrypt: %w", err))
	}

	// nodes create decryption shares with proofs for the ciphertext
	decShares := make([]*tdh2.DecryptionShare, 0, k)
	for i := 0; i < k; i++ {
		ds, err := ctxt.Decrypt(group, shares[i], newStream())
		if err != nil {
			panic(fmt.Errorf("decrypt share %d: %w", i, err))
		}
		decShares = append(decShares, ds)
	}

	// server combines verified shares to recover the message
	recovered, err := ctxt.CombineShares(group, decShares, k, n)
	if err != nil {
		panic(fmt.Errorf("combine: %w", err))
	}

	fmt.Printf("original message: %s\n", msg)
	fmt.Printf("recovered message: %s\n", recovered)
}
