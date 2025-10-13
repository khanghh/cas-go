package render

type LoginPageData struct {
	Identifier     string
	OAuthLoginURLs map[string]string
	ErrorMsg       string
}

type RegisterPageData struct {
	Username      string
	Email         string
	FullName      string
	Picture       string
	OAuthProvider string
	FormErrors    map[string]string
	ErrorMsg      string
}

type VerificationRequiredPageData struct {
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
	IsMasked bool
	Email    string
	Phone    string
	ErrorMsg string
}

type AuthorizeServicePageData struct {
	Username    string
	FullName    string
	Email       string
	ServiceName string
	ServiceURL  string
}

type ForgotPasswordPageData struct {
	Email     string
	EmailSent bool
	ErrorMsg  string
}

type HomePageData struct {
	Username string
	FullName string
	Email    string
}
