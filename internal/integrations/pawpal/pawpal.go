package pawpal

import (
	"crypto/subtle"
	"fmt"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
	maxSafeInteger                     = 9_007_199_254_740_991
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey string, expectedKey string, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	if orderID <= 0 || orderID > maxSafeInteger {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	payloadStatus, ok := payloadRecord["status"]
	if !ok || payloadStatus != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
