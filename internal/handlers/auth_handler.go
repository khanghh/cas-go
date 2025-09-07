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
	serviceRegistry  ServiceRegistry
	authorizeService AuthorizeService
	userService      UserService
}

func NewAuthHandler(serviceRegistry ServiceRegistry, authorizeService AuthorizeService, userService UserService) *AuthHandler {
	return &AuthHandler{
		serviceRegistry:  serviceRegistry,
		authorizeService: authorizeService,
		userService:      userService,
	}
}

func (h *AuthHandler) createUserSession(ctx *fiber.Ctx, user *model.User, userOAuth *model.UserOAuth) sessions.SessionData {
	sessions.Destroy(ctx)
	session := sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	}
	if userOAuth != nil {
		session.OAuthID = userOAuth.ID
	}
	sessions.Set(ctx, session)
	return session
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
	if !session.IsAuthenticated() {
		return render.RenderHomePage(ctx)
	}
	return redirect(ctx, "/login", nil)
}
