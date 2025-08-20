package render

type LoginPageData struct {
	OAuthURLs  map[string]string
	Identifier string
	LoginError string
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
