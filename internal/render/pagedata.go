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
