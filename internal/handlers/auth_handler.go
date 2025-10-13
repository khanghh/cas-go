package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, session *sessions.Session, serviceURL string, challengeRequired bool) error {
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), session.UserID, serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return redirect(ctx, "/login")
	} else if err != nil {
		return err
	}

	redirectURL := appendQuery(serviceURL, "ticket", ticket.TicketID)

	if challengeRequired {
		challengeOpts := twofactor.ChallengeOptions{
			Subject:     getChallengeSubject(ctx, session),
			RedirectURL: redirectURL,
			ExpiresIn:   5 * time.Minute,
		}
		ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), challengeOpts)
		if err != nil {
			return err
		}
		return redirect(ctx, "/2fa/challenge", "cid", ch.ID)
	}

	return ctx.Redirect(redirectURL)
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
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
	authorize := ctx.FormValue("authorize")

	if serviceURL == "" {
		return render.RenderNotFoundError(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	if authorize != "true" {
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

	challengeRequired := service.ChallengeRequired && time.Since(session.TwoFASuccessAt) > service.ChallengeValidity
	return h.handleAuthorizeServiceAccess(ctx, session, serviceURL, challengeRequired)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	return render.RenderHomePage(ctx, render.HomePageData{
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
