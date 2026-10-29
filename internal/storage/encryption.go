package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

const (
	nonceSize = 12
	tagSize   = 16
)

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	return encrypt(plaintext, key, rand.Reader)
}

func encrypt(plaintext []byte, key [32]byte, randomSource io.Reader) (EncryptedPayload, error) {
	blockCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create authenticated encryption: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate encryption nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[len(sealed)-tagSize:],
		Ciphertext: sealed[:len(sealed)-tagSize],
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != nonceSize {
		return nil, errors.New("invalid nonce length")
	}

	if len(payload.AuthTag) != tagSize {
		return nil, errors.New("invalid tag length")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	reconstructedValue := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	reconstructedValue = append(reconstructedValue, payload.Ciphertext...)
	reconstructedValue = append(reconstructedValue, payload.AuthTag...)

	opened, err := aead.Open(nil, payload.Nonce, reconstructedValue, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return opened, nil
}
