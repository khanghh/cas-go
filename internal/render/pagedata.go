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
	EmailEnabled bool
	SMSEnableled bool
	TOTPEnabled  bool
	IsMasked     bool
	Email        string
	Phone        string
}
