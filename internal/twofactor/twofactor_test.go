package twofactor

import (
	"fmt"
	"testing"

	"github.com/gofiber/storage/memory/v2"
)

func TestVerifyOTP(t *testing.T) {
	var (
		uid              = uint(1)
		binding          = BindingValues{uid, "login", "svc1.example.com"}
		twoFactorService = NewTwoFactorService(memory.New(), "xxx")
	)

	ch, otpCode := twoFactorService.OTP().Create()
	fmt.Printf("otp code: %v\n", otpCode)
	if err := twoFactorService.SetUserChallenge(uid, ch, binding); err != nil {
		t.Fatal(err)
	}

	result, err := twoFactorService.VerifyChallenge(uid, ch.ID, binding, otpCode)
	if err != nil {
		t.Fatal(err)
	}
	if result.Success {
		fmt.Println("challenge is success")
	} else {
		fmt.Printf("challenge is failed, attmept left: %v\n", result.AttemptsLeft)
	}
}
