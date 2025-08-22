package handlers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler handles authentication and authorization
type LoginHandler struct {
	*BaseAuthHandler
	serviceRegistry  ServiceRegistry
	authorizeService AuthorizeService
	userService      UserService
}

// NewLoginHandler returns a new instance of AuthHandler.
func NewLoginHandler(baseAuthHander *BaseAuthHandler, serviceRegistry ServiceRegistry, authorizeService AuthorizeService, userService UserService) *LoginHandler {
	return &LoginHandler{
		BaseAuthHandler:  baseAuthHander,
		serviceRegistry:  serviceRegistry,
		authorizeService: authorizeService,
		userService:      userService,
	}
}

func (h *LoginHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	renew := ctx.QueryBool("renew")

	session := sessions.Get(ctx)
	if renew {
		sessions.Destroy(ctx)
	} else if session.UserID != 0 {
		if user, err := h.userService.GetUserByID(ctx.Context(), session.UserID); err == nil {
			return h.handleAuthorizeServiceAccess(ctx, user, serviceURL)
		}
	}

	return render.RenderLogin(ctx, render.LoginPageData{})
}

func (h *LoginHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	pageData := render.LoginPageData{Identifier: username}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), username)
	if err != nil {
		pageData.LoginError = "Invalid username or password"
		return render.RenderLogin(ctx, pageData)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		pageData.LoginError = "Invalid username or password"
		return render.RenderLogin(ctx, pageData)
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})
	return h.handleAuthorizeServiceAccess(ctx, user, serviceURL)
}

func (h *LoginHandler) PostLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return ctx.Redirect("/login")
}

func (h *LoginHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, serviceURL string) error {
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
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
