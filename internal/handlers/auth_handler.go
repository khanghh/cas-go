package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	challengeService *twofactor.ChallengeService
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, challengeService *twofactor.ChallengeService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		challengeService: challengeService,
	}
}

func createUserSession(ctx *fiber.Ctx, user *model.User, userOAuth *model.UserOAuth) *sessions.Session {
	session := sessions.Get(ctx)
	sessionData := sessions.SessionData{
		IP:            ctx.IP(),
		UserID:        user.ID,
		LoginTime:     time.Now(),
		TwoFARequired: true,
	}
	if userOAuth != nil {
		sessionData.OAuthID = userOAuth.ID
		sessionData.TwoFARequired = false
	}
	sessions.Reset(ctx, sessionData)
	return session
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return render.RenderNotFoundError(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login", "service", serviceURL)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx)
	}

	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), user.ID, serviceURL)
	if errors.Is(err, auth.ErrServiceNotFound) {
		return redirect(ctx, "/login")
	} else if err != nil {
		return err
	}
	return redirect(ctx, ticket.CallbackURL, "ticket", ticket.TicketID)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx)
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
	serviceURL := ctx.Query("service")
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
