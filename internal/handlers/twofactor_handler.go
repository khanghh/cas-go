package handlers

import (
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

const (
	totpEnrollSecretSessionKey = "_totp_enroll_secret"
)

type TwoFactorHandler struct {
	twoFactorService TwoFactorService
	userService      UserService
	mailSender       mail.MailSender
}

func (h *TwoFactorHandler) renderVerifyOTP(ctx *fiber.Ctx, email string, errorMsg string) error {
	pageData := render.VerifyOTPPageData{
		Email:    email,
		IsMasked: true,
		ErrorMsg: errorMsg,
	}
	return render.RenderVerifyOTP(ctx, pageData)
}

func mapTwoFactorError(err error) (string, bool) {
	if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
		return MsgTooManyFailedAttempts, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestLimitReached) {
		return MsgTooManyOTPRequested, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestRateLimited) {
		return MsgOTPRequestRateLimited, true
	}
	var verifyErr *twofactor.AttemptFailError
	if errors.As(err, &verifyErr) {
		return fmt.Sprintf(MsgInvalidOTP, verifyErr.AttemptsLeft), true
	}
	return "", false
}

func getChallengeSubject(ctx *fiber.Ctx, session *sessions.Session) twofactor.Subject {
	return twofactor.Subject{
		UserID:    session.UserID,
		SessionID: session.ID(),
		IPAddress: ctx.IP(),
		UserAgent: ctx.Get("User-Agent"),
	}
}

func (h *TwoFactorHandler) GetChallenge(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if encryptedState == "" {
		return render.RenderNotFoundError(ctx)
	}
	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if time.Since(time.Unix(0, state.Timestamp)) > 5*time.Minute {
		// TODO: if this is 2fa login, logout user when it's expired
		return render.RenderNotFoundError(ctx)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	authFactors, err := h.userService.GetAuthFactors(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	pageData := render.VerificationRequiredPageData{
		Email:        user.Email,
		EmailEnabled: isFactorEnabled(authFactors, string(users.AuthFactorEmail)),
		TOTPEnabled:  isFactorEnabled(authFactors, string(users.AuthFactorTOTP)),
		IsMasked:     true,
	}
	return render.RenderVerificationRequired(ctx, pageData)
}

func (h *TwoFactorHandler) generateAndSendEmailOTP(ctx *fiber.Ctx, ch *twofactor.Challenge, sub twofactor.Subject, email string) error {
	otpCode, err := h.twoFactorService.OTP().Generate(ctx.Context(), ch, sub)
	if err != nil {
		return err
	}
	return mail.SendOTP(h.mailSender, email, otpCode)
}

func (h *TwoFactorHandler) handleChallengeEmailOTP(ctx *fiber.Ctx, pageData render.VerificationRequiredPageData, sub twofactor.Subject, callbackURL string, createCallback func(ch *twofactor.Challenge) error) error {
	otpCode, ch, err := h.twoFactorService.OTP().Create(ctx.Context(), sub, callbackURL, 5*time.Minute)
	if err != nil {
		if errMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errMsg
			return render.RenderVerificationRequired(ctx, pageData)
		}
		return err
	}
	if err := mail.SendOTP(h.mailSender, pageData.Email, otpCode); err != nil {
		pageData.ErrorMsg = "Failed to send email"
		return render.RenderVerificationRequired(ctx, pageData)
	}
	if err := createCallback(ch); err != nil {
		return err
	}
	return redirect(ctx, "/2fa/otp/verify", "cid", ch.ID)
}

func (h *TwoFactorHandler) handleChallengeTOTP(ctx *fiber.Ctx, pageData render.VerificationRequiredPageData, sub twofactor.Subject, callbackURL string, createCallback func(ch *twofactor.Challenge) error) error {
	ch, err := h.twoFactorService.TOTP().Create(ctx.Context(), sub, callbackURL, 5*time.Minute)
	if err != nil {
		if errMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errMsg
			return render.RenderVerificationRequired(ctx, pageData)
		}
		return err
	}
	if err := createCallback(ch); err != nil {
		return err
	}
	return redirect(ctx, "/2fa/totp/verify", "cid", ch.ID)
}

func (h *TwoFactorHandler) handleChallengeSuccess(ctx *fiber.Ctx, session *sessions.Session, ch *twofactor.Challenge, sub twofactor.Subject) error {
	if session.TwoFARequired && session.TwoFAChallengeID == ch.ID {
		session.TwoFARequired = false
		session.TwoFASuccessAt = time.Now()
		session.Save()
	}
	return redirect(ctx, ch.CallbackURL, "cid", ch.ID)
}

func (h *TwoFactorHandler) PostChallenge(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")
	method := ctx.FormValue("method")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if encryptedState == "" {
		return render.RenderNotFoundError(ctx)
	}
	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if time.Since(time.Unix(0, state.Timestamp)) > 5*time.Minute {
		// TODO: if this is 2fa login, logout user when it's expired
		return render.RenderNotFoundError(ctx)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	pageData := render.VerificationRequiredPageData{
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
	}
	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		return render.RenderVerificationRequired(ctx, pageData)
	}

	postCreateFunc := func(ch *twofactor.Challenge) error {
		if state.Action == "login" && session.TwoFARequired {
			session.TwoFAChallengeID = ch.ID
			session.Save()
		}
		return nil
	}

	sub := getChallengeSubject(ctx, session)
	switch method {
	case "email":
		return h.handleChallengeEmailOTP(ctx, pageData, sub, state.CallbackURL, postCreateFunc)
	case "totp":
		return h.handleChallengeTOTP(ctx, pageData, sub, state.CallbackURL, postCreateFunc)
	default:
		pageData.ErrorMsg = MsgInvalid2FAMethod
		return render.RenderVerificationRequired(ctx, pageData)
	}
}

func (h *TwoFactorHandler) GetVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	sub := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, sub, twofactor.ChallengeTypeOTP); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return h.renderVerifyOTP(ctx, user.Email, "")
}

func (h *TwoFactorHandler) PostVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	code := ctx.FormValue("code")
	resend := ctx.FormValue("resend") != ""

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	if !resend && code == "" {
		return h.renderVerifyOTP(ctx, user.Email, MsgOTPCodeEmpty)
	}
	if !csrf.Verify(ctx) {
		return h.renderVerifyOTP(ctx, user.Email, MsgInvalidRequest)
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject, twofactor.ChallengeTypeOTP); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	handleTwoFactorError := func(ctx *fiber.Ctx, err error) error {
		if errors.Is(err, twofactor.ErrChallengeSubjectMismatch) {
			return render.RenderNotFoundError(ctx)
		}
		if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
			if !session.IsAuthenticated() {
				return forceLogout(ctx, "tfa_failed")
			}
			return ctx.Redirect("/")
		}
		if msg, ok := mapTwoFactorError(err); ok {
			return h.renderVerifyOTP(ctx, user.Email, msg)
		}
		return err
	}

	if resend {
		err = h.generateAndSendEmailOTP(ctx, ch, subject, user.Email)
		if err != nil {
			return handleTwoFactorError(ctx, err)
		}
		return redirect(ctx, "/2fa/verify-otp", "cid", ch.ID)
	}

	if err := h.twoFactorService.OTP().Verify(ctx.Context(), ch, subject, code); err != nil {
		return handleTwoFactorError(ctx, err)
	}

	return h.handleChallengeSuccess(ctx, session, ch, subject)
}

func (h *TwoFactorHandler) generateTOTPEnrollmentURL(issuer string, username string, secret string) (string, error) {
	base32Secret, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		Period:      30,
		Secret:      base32Secret,
	})

	if err != nil {
		return "", err
	}
	return key.String(), nil
}

func (h *TwoFactorHandler) GetTOTPEnroll(ctx *fiber.Ctx) error {
	renew := ctx.Query("renew")
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	secret, ok := session.Get(totpEnrollSecretSessionKey).(string)
	if !ok || renew == "true" {
		secret = h.twoFactorService.TOTP().GenerateSecret()
		session.Set(totpEnrollSecretSessionKey, secret)
	}

	issuer := ctx.Locals("siteName").(string)
	enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
	if err != nil {
		return err
	}

	pageData := render.TOTPEnrollmentPageData{
		SecretKey:     secret,
		EnrollmentURL: enrollmentURL,
	}
	return render.RenderTOTPEnrollment(ctx, pageData)
}

func (h *TwoFactorHandler) PostTOTPEnroll(ctx *fiber.Ctx) error {
	code := ctx.FormValue("verificationCode")

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	if !csrf.Verify(ctx) {
		return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	secret, ok := session.Get(totpEnrollSecretSessionKey).(string)
	if !ok {
		return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
	}

	err = h.twoFactorService.TOTP().Enroll(ctx.Context(), session.UserID, secret, code)
	if err != nil {
		if errors.Is(err, twofactor.ErrTOTPVerifyFailed) {
			errMsg := MsgTOTPEnrollFailed
			issuer := ctx.Locals("siteName").(string)
			enrollmentURL, err := h.generateTOTPEnrollmentURL(issuer, user.Username, secret)
			if err != nil {
				return err
			}
			pageData := render.TOTPEnrollmentPageData{
				SecretKey:     secret,
				EnrollmentURL: enrollmentURL,
				ErrorMsg:      errMsg,
			}
			return render.RenderTOTPEnrollment(ctx, pageData)
		}
		return err
	}

	session.Delete(totpEnrollSecretSessionKey)
	return render.RenderTOTPEnrollSuccess(ctx)
}

func (h *TwoFactorHandler) GetTOTVerify(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	sub := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, sub, twofactor.ChallengeTypeTOTP); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return render.RenderVerifyTOTP(ctx, "")
}

func (h *TwoFactorHandler) PostTOTPVerify(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	code := ctx.FormValue("code")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	if !csrf.Verify(ctx) {
		return render.RenderVerifyTOTP(ctx, MsgInvalidRequest)
	}

	if code == "" {
		return render.RenderVerifyTOTP(ctx, MsgOTPCodeEmpty)
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject, twofactor.ChallengeTypeTOTP); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	handleTwoFactorError := func(ctx *fiber.Ctx, err error) error {
		if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
			if !session.IsAuthenticated() {
				return forceLogout(ctx, "tfa_failed")
			}
		}
		if msg, ok := mapTwoFactorError(err); ok {
			return render.RenderVerifyTOTP(ctx, msg)
		}
		return err
	}

	if err := h.twoFactorService.TOTP().Verify(ctx.Context(), ch, subject, code); err != nil {
		return handleTwoFactorError(ctx, err)
	}

	return h.handleChallengeSuccess(ctx, session, ch, subject)
}

func isFactorEnabled(authFactors []*model.UserFactor, factorType string) bool {
	for _, factor := range authFactors {
		if factor.Type == factorType && factor.Enabled {
			return true
		}
	}
	return false
}

func (h *TwoFactorHandler) GetTwoFASettings(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}
	authFactors, err := h.userService.GetAuthFactors(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	pageData := render.TwoFASettingsPageData{
		Email:        user.Email,
		EmailEnabled: isFactorEnabled(authFactors, "email"),
		TOTPEnabled:  isFactorEnabled(authFactors, "totp"),
	}
	return render.Render2FASettings(ctx, pageData)
}

func (h *TwoFactorHandler) PostTwoFASettings(ctx *fiber.Ctx) error {
	emailEnabled := ctx.FormValue("emailEnabled") == "true"
	totpEnabled := ctx.FormValue("totpEnabled") == "true"

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return forceLogout(ctx, "")
	}

	if !csrf.Verify(ctx) {
		return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	err = h.userService.SetAuthFactorEnabled(ctx.Context(), session.UserID, users.AuthFactorEmail, emailEnabled)
	if err != nil {
		return err
	}

	err = h.userService.SetAuthFactorEnabled(ctx.Context(), session.UserID, users.AuthFactorTOTP, totpEnabled)
	if totpEnabled && errors.Is(err, users.ErrAuthFactorNotSetup) {
		return ctx.Redirect("/2fa/totp/enroll", fiber.StatusFound)
	}

	return ctx.Redirect(ctx.OriginalURL(), fiber.StatusFound)
}

func NewTwoFactorHandler(twoFactorService TwoFactorService, userService UserService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		twoFactorService: twoFactorService,
		userService:      userService,
		mailSender:       mailSender,
	}
}
