package orders

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/storage"
)

type ShippingDetails struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	City       string `json:"city"`
	Region     string `json:"region"`
	PostalCode string `json:"postalCode"`
}

type serializedShippingDetails struct {
	Name       *string `json:"name"`
	Address    *string `json:"address"`
	City       *string `json:"city"`
	Region     *string `json:"region"`
	PostalCode *string `json:"postalCode"`
}

func EncryptShippingDetails(details ShippingDetails, encryptionKeyring *storage.Keyring) (string, error) {
	plaintext, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("serialize shipping details: %w", err)
	}
	encrypted, err := encryptionKeyring.Encrypt([]byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("encrypting shipping details: %w", err)
	}
	return encrypted, nil
}

func DecryptShippingDetails(serialized string, encryptionKeyring *storage.Keyring) (ShippingDetails, error) {
	decrypted, err := encryptionKeyring.Decrypt(serialized)
	if err != nil {
		return ShippingDetails{}, fmt.Errorf("decrypting serialized payload: %w", err)
	}
	var details serializedShippingDetails
	if err := json.Unmarshal(decrypted, &details); err != nil || details.Name == nil || details.Address == nil || details.City == nil || details.Region == nil || details.PostalCode == nil {
		return ShippingDetails{}, errors.New("invalid shipping details")
	}
	return ShippingDetails{
		Name:       *details.Name,
		Address:    *details.Address,
		City:       *details.City,
		Region:     *details.Region,
		PostalCode: *details.PostalCode,
	}, nil
}
