package render

type LoginPageData struct {
	Identifier     string
	LoginError     string
	OAuthLoginURLs map[string]string
}

type RegisterPageData struct {
	Username      string
	Email         string
	FullName      string
	Picture       string
	OAuthProvider string
	FormErrors    map[string]string
}

type VerificationRequiredPageData struct {
	ChallengeID  string
	EmailEnabled bool
	SMSEnableled bool
	TOTPEnabled  bool
	IsMasked     bool
	Email        string
	Phone        string
}

type VerifyOTPPageData struct {
	ChallengeID string
	IsMasked    bool
	Email       string
	Phone       string
	CSRFToken   string
	VerifyError string
}

type HomePageData struct {
	Username string
	FullName string
	Email    string
}
