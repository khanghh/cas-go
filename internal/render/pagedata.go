package render

type OnboardingPageData struct {
	Username      string
	Email         string
	FullName      string
	Picture       string
	UsernameError string
	PasswordError string
	EmailError    string
}

type LoginPageData struct {
	OAuthURLs  map[string]string
	Identifier string
	LoginError string
}
