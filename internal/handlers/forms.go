package handlers

type RegisterForm struct {
	Username string `form:"username"`
	Password string `form:"password"`
	Email    string `form:"email"`
}

func (form *RegisterForm) Validate() map[string]string {
	formErrors := make(map[string]string)
	if err := validateUsername(form.Username); err != nil {
		formErrors["username"] = err.Error()
	}

	if err := validatePassword(form.Password); err != nil {
		formErrors["password"] = err.Error()
	}

	if err := validateEmail(form.Email); err != nil {
		formErrors["email"] = err.Error()
	}
	return formErrors
}
