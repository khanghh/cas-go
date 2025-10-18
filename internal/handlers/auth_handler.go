package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/common"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

func (h *AuthHandler) getAuthorizedTime(ctx *fiber.Ctx, serviceURL string) time.Time {
	session := sessions.Get(ctx)
	key := "authz:" + common.CalculateHash(session.StateEncryptionKey, serviceURL)
	nsec, ok := session.Get(key).(int64)
	if ok {
		return time.Unix(0, nsec)
	}
	return time.Time{}
}

func (h *AuthHandler) setAuthorizedTime(ctx *fiber.Ctx, serviceURL string, expiresAt time.Time) {
	session := sessions.Get(ctx)
	key := "authz:" + common.CalculateHash(session.StateEncryptionKey, serviceURL)
	session.Set(key, expiresAt.UnixNano())
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, session *sessions.Session, serviceURL string) error {
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), session.UserID, serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderDeniedError(ctx)
	} else if err != nil {
		return err
	}
	return redirect(ctx, ticket.ServiceURL, "ticket", ticket.TicketID)
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")
	serviceURL := sanitizeURL(ctx.Query("service"))
	if serviceURL == "" {
		return render.RenderNotFoundError(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	service, err := h.authorizeService.GetService(ctx.Context(), serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundError(ctx)
	} else if err != nil {
		return err
	}

	authorizeTime := h.getAuthorizedTime(ctx, service.LoginURL)
	challengeRequired := service.ChallengeRequired && time.Since(authorizeTime) > service.ChallengeValidity
	if !challengeRequired && service.AutoLogin {
		return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
	}
	if challengeRequired && cid != "" {
		sub := getChallengeSubject(ctx, sessions.Get(ctx))
		endpoint := appendQuery("/authorize", "service", serviceURL)
		err = h.twoFactorService.FinalizeChallenge(ctx.Context(), cid, sub, endpoint)
		if err == nil {
			h.setAuthorizedTime(ctx, serviceURL, time.Now())
			return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
		}
	}

	pageData := render.AuthorizeServicePageData{
		Email:       user.Email,
		ServiceName: service.Name,
		ServiceURL:  service.LoginURL,
	}
	return render.RenderAuthorizeServiceAccess(ctx, pageData)
}

func (h *AuthHandler) PostAuthorize(ctx *fiber.Ctx) error {
	serviceURL := sanitizeURL(ctx.Query("service"))
	confirm := ctx.FormValue("confirm")

	if serviceURL == "" {
		return render.RenderNotFoundError(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	if confirm != "true" {
		return ctx.Redirect("/")
	}

	_, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	service, err := h.authorizeService.GetService(ctx.Context(), serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return render.RenderNotFoundError(ctx)
	}

	challengeRequired := service.ChallengeRequired && time.Since(h.getAuthorizedTime(ctx, service.LoginURL)) > service.ChallengeValidity
	if challengeRequired {
		state := TwoFactorState{
			Action:      "authorize",
			CallbackURL: appendQuery("/authorize", "service", serviceURL),
			Timestamp:   time.Now().UnixNano(),
		}
		return redirect(ctx, "/2fa/challenge", "state", encryptState(ctx, state))
	}

	h.setAuthorizedTime(ctx, service.LoginURL, time.Now())
	return h.handleAuthorizeServiceAccess(ctx, session, serviceURL)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsAuthenticated() {
		return redirect(ctx, "/profile")
	}
	return redirect(ctx, "/login")
}

func (h *AuthHandler) GetProfile(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	return render.RnderProfilePage(ctx, render.HomePageData{
		Username: user.Username,
		FullName: user.FullName,
		Email:    user.Email,
	})
}

type UserInfoResponse struct {
	UserID   uint   `json:"userId"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
}

func (h *AuthHandler) GetServiceValidate(ctx *fiber.Ctx) error {
	ticketID := ctx.Query("ticket")
	serviceURL := sanitizeURL(ctx.Query("service"))
	signature := string(ctx.Request().Header.Peek("X-Signature"))
	timestamp := string(ctx.Request().Header.Peek("X-Timestamp"))

	if ticketID == "" || serviceURL == "" || signature == "" || timestamp == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(APIResponse{
			Error: &ErrorResponse{
				Code:    fiber.StatusBadRequest,
				Message: "missing required parameter",
			},
		})
	}

	ticket, err := h.authorizeService.ValidateServiceTicket(ctx.Context(), serviceURL, ticketID, timestamp, signature)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(APIResponse{
			Error: &ErrorResponse{
				Code:    fiber.StatusUnauthorized,
				Message: err.Error(),
			},
		})
	}

	user, err := h.userService.GetUserByID(ctx.Context(), ticket.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(APIResponse{
			Error: &ErrorResponse{
				Code:    fiber.StatusUnauthorized,
				Message: err.Error(),
			},
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(APIResponse{
		Data: UserInfoResponse{
			UserID:   user.ID,
			Username: user.Username,
			FullName: user.FullName,
			Email:    user.Email,
			Picture:  user.Picture,
		},
	})
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twoFactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twoFactorService,
	}
}
