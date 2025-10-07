package render

type LoginPageData struct {
	CSRFToken      string
	Identifier     string
	OAuthLoginURLs map[string]string
	ErrorMsg       string
}

type RegisterPageData struct {
	CSRFToken     string
	Username      string
	Email         string
	FullName      string
	Picture       string
	OAuthProvider string
	FormErrors    map[string]string
	ErrorMsg      string
}

type VerificationRequiredPageData struct {
	CSRFToken    string
	ChallengeID  string
	EmailEnabled bool
	SMSEnableled bool
	TOTPEnabled  bool
	IsMasked     bool
	Email        string
	Phone        string
	ErrorMsg     string
}

type VerifyOTPPageData struct {
	CSRFToken string
	IsMasked  bool
	Email     string
	Phone     string
	ErrorMsg  string
}

type HomePageData struct {
	Username string
	FullName string
	Email    string
}
