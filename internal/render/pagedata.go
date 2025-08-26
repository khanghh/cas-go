package render

type LoginPageData struct {
	Identifier     string
	LoginError     string
	OAuthLoginURLs map[string]string
}

type RegisterPageData struct {
	Username      string
	Email         string
	UsernameError string
	PasswordError string
	EmailError    string
}

type OnboardingPageData struct {
	Username      string
	Email         string
	FullName      string
	Picture       string
	UsernameError string
	PasswordError string
	EmailError    string
}
