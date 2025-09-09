package twofactor

import (
	"fmt"
	"testing"
	"time"

	"github.com/gofiber/storage/memory/v2"
)

func TestCreateOTP(t *testing.T) {
	var (
		uid              = uint(1)
		binding          = BindingValues{uid, "login", "svc1.example.com"}
		twoFactorService = NewTwoFactorService(memory.New(), "xxx")
	)

	// Setup challenge
	otps := ChallengeOptions{
		UserID:      uid,
		Binding:     binding,
		Method:      "login",
		RedirectURL: "svc1.example.com",
		ExpiresIn:   5 * time.Minute,
	}
	ch, err := twoFactorService.CreateChallenge(otps)
	if err != nil {
		t.Fatal(err)
	}
	otpCode, err := twoFactorService.PrepareOTP(uid, ch)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("otp code: %v\n", otpCode)

	// Verify challenge
	result, err := twoFactorService.VerifyChallenge(uid, ch, binding, otpCode)
	if err != nil {
		t.Fatal(err)
	}
	if result.Success {
		fmt.Println("challenge is success")
	} else {
		fmt.Printf("challenge is failed, attmept left: %v\n", result.AttemptsLeft)
	}
}

func TestVerifyOTP(t *testing.T) {
	var (
		cid              = "123"
		uid              = uint(1)
		binding          = BindingValues{uid, "login", "svc1.example.com"}
		twoFactorService = NewTwoFactorService(memory.New(), "xxx")
	)

	ch, err := twoFactorService.GetChallenge(cid)
	if err != nil {
		t.Fatal("Challenge not found")
	}

	result, err := twoFactorService.VerifyChallenge(uid, ch, binding, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if result.Success {
		fmt.Println("challenge is success")
	} else {
		fmt.Printf("challenge is failed, attmept left: %v\n", result.AttemptsLeft)
	}
}
