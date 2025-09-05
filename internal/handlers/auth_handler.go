package handlers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
)

type AuthHandler struct {
	serviceRegistry    ServiceRegistry
	authorizeService   AuthorizeService
	userService        UserService
	stateEncryptionKey string
}

func NewAuthHandler(serviceRegistry ServiceRegistry, authorizeService AuthorizeService, userService UserService, stateEncryptionKey string) *AuthHandler {
	return &AuthHandler{
		serviceRegistry:    serviceRegistry,
		authorizeService:   authorizeService,
		userService:        userService,
		stateEncryptionKey: stateEncryptionKey,
	}
}

func (h *AuthHandler) createUserSession(ctx *fiber.Ctx, user *model.User, userOAuth *model.UserOAuth) error {
	sessions.Destroy(ctx)
	var oauthID uint
	if userOAuth != nil {
		oauthID = userOAuth.ID
	}
	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		OAuthID:   oauthID,
		LoginTime: time.Now(),
	})
	return nil
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, serviceURL string) error {
	baseServiceURL, err := parseServiceURL(serviceURL)
	if err != nil {
		return render.RenderUnauthorizedError(ctx)
	}

	service, err := h.serviceRegistry.GetService(ctx.Context(), baseServiceURL)
	if err != nil {
		return render.RenderUnauthorizedError(ctx)
	}

	callbackURL := baseServiceURL
	if service.StripQuery {
		callbackURL = serviceURL
	}
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), user.ID, callbackURL)
	if err != nil {
		return err
	}

	redirectURL := fmt.Sprintf("%s?ticket=%s", ticket.CallbackURL, ticket.TicketID)
	return ctx.Redirect(redirectURL)
}

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	service := ctx.Query("service")
	if service == "" {
		return ctx.Redirect("/")
	}

	session := sessions.Get(ctx)
	if session.UserID == 0 {
		return redirect(ctx, "/login", fiber.Map{"service": service})
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return render.RenderUnauthorizedError(ctx)
	}
	return h.handleAuthorizeServiceAccess(ctx, user, service)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return render.RenderHomePage(ctx)
	}
	return redirect(ctx, "/login", nil)
}
