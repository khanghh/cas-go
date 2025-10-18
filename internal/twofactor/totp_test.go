package twofactor

import (
	"fmt"
	"testing"

	"github.com/pquerna/otp/totp"
)

func TestXxx(t *testing.T) {
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example",
		AccountName: "aaa",
		Period:      30,
		Secret:      []byte(randomSecretKey(32)),
	})
	fmt.Println(key.String())
}
