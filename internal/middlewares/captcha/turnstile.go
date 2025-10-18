package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type TurnstileVerifier struct {
	SecretKey string
}

type turnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	Cdata       string   `json:"cdata"`
}

func (v *TurnstileVerifier) doVerify(ctx context.Context, response string, remoteIP string) (*turnstileResponse, error) {
	payload := map[string]string{
		"secret":   v.SecretKey,
		"response": response,
	}
	if remoteIP != "" {
		payload["remoteip"] = remoteIP
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("turnstile verify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("turnstile verify bad status: %d", resp.StatusCode)
	}

	var result turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode turnstile response: %w", err)
	}

	return &result, nil
}

func (v *TurnstileVerifier) Verify(ctx *fiber.Ctx) error {
	response := ctx.FormValue("cf-turnstile-response")
	remoteIP := ctx.Get("CF-Connecting-IP")
	if remoteIP == "" {
		remoteIP = ctx.Get("X-Forwarded-For")
	}

	result, err := v.doVerify(ctx.Context(), response, remoteIP)
	if err != nil {
		slog.Error("Captcha verify error", "error", err)
		return ErrInvalidCaptcha
	}

	if !result.Success {
		slog.Debug("Captcha verify failed", "remoteIP", remoteIP, "reason", result.ErrorCodes)
		return ErrInvalidCaptcha
	}

	return nil
}

func NewTurnstileVerifier(secret string) *TurnstileVerifier {
	return &TurnstileVerifier{
		SecretKey: secret,
	}
}
