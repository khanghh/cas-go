package handlers

type OnboardingForm struct {
	Username string `form:"username"`
	Password string `form:"password"`
	Email    string `form:"email"`
	FullName string `form:"fullName"`
	Picture  string `form:"picture"`
}
