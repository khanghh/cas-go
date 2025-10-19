package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/redis/v3"
	"github.com/gofiber/template/html/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/common"
	"github.com/khanghh/cas-go/internal/config"
	"github.com/khanghh/cas-go/internal/handlers"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares"
	"github.com/khanghh/cas-go/internal/middlewares/captcha"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"github.com/khanghh/cas-go/params"
	"github.com/urfave/cli/v2"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"gorm.io/gorm/schema"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	app       *cli.App
	gitCommit string
	gitDate   string
	gitTag    string
)

var (
	configFileFlag = &cli.StringFlag{
		Name:  "config",
		Usage: "YAML config file",
		Value: "config.yaml",
	}
	debugFlag = &cli.BoolFlag{
		Name:  "debug",
		Usage: "Enable debug logging",
	}
)

func init() {
	app = cli.NewApp()
	app.EnableBashCompletion = true
	app.Usage = "CAS Server"
	app.Flags = []cli.Flag{
		configFileFlag,
		debugFlag,
	}
	app.Commands = []*cli.Command{
		{
			Name: "version",
			Action: func(ctx *cli.Context) error {
				fmt.Println(params.VersionWithCommit(gitCommit, gitDate))
				return nil
			},
		},
	}
	app.Action = run
}

func mustInitLogger(debug bool) {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))
}

func mustInitDatabase(dbConfig config.MySQLConfig) *gorm.DB {
	db, err := gorm.Open(mysql.Open(dbConfig.Dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   dbConfig.TablePrefix,
			SingularTable: true,
		},
	})
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	if err := db.AutoMigrate(model.Models...); err != nil {
		slog.Error("Database migration failed", "error", err)
		os.Exit(1)
	}

	return db
}

func mustInitOAuthProviders(config *config.Config) []oauth.OAuthProvider {
	var providers []oauth.OAuthProvider
	for providerName, providerCfg := range config.AuthProviders.OAuth {
		callbackURL, _ := url.JoinPath(config.BaseURL, "oauth", providerName, "callback")
		switch providerName {
		case "google":
			provider := oauth.NewGoogleOAuthProvider(callbackURL, providerCfg.ClientID, providerCfg.ClientSecret)
			providers = append(providers, provider)
		default:
			slog.Error("Unsupported OAuth provider", "provider", providerName)
			os.Exit(1)
		}
	}
	return providers
}

func mustInitHtmlEngine(templateDir string) *html.Engine {
	var htmlEngine *html.Engine
	if templateDir != "" {
		htmlEngine = html.NewFileSystem(http.Dir(templateDir), ".html")
	} else {
		renderFS, _ := fs.Sub(templateFS, "templates")
		htmlEngine = html.NewFileSystem(http.FS(renderFS), ".html")
	}
	return htmlEngine
}

func mustInitSMTPMailSender(config config.SMTPConfig) mail.MailSender {
	dialer := gomail.NewDialer(config.Host, config.Port, config.Username, config.Password)
	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	if config.TLS {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			panic(err)
		}

		caPool := x509.NewCertPool()
		if config.CAFile != "" {
			caCert, err := os.ReadFile(config.CAFile)
			if err != nil {
				panic(err)
			}
			caPool.AppendCertsFromPEM(caCert)
		}

		dialer.TLSConfig = &tls.Config{
			ServerName:         config.Host,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caPool,
		}
	}
	return mail.NewSMTPMailSender(dialer, config.From)
}

func mustInitMailSender(config config.MailConfig) mail.MailSender {
	if config.Backend == "" {
		log.Fatal("Missing mail sender backend")
	}
	if config.Backend == "smtp" {
		return mustInitSMTPMailSender(config.SMTP)
	}
	log.Fatalf("Unsupported mail sender backend %s", config.Backend)
	return nil
}

func mustInitCaptchaVerifier(config config.CaptchaConfig) captcha.CaptchaVerifier {
	if config.Provider == "turnstile" {
		return captcha.NewTurnstileVerifier(config.Turnstile.SecretKey)
	}
	return captcha.NewNullVerifier()
}

func run(ctx *cli.Context) error {
	config, err := config.LoadConfig(ctx.String(configFileFlag.Name))
	if err != nil {
		slog.Error("Could not load config file.", "error", err)
		return err
	}

	mustInitLogger(config.Debug || ctx.IsSet(debugFlag.Name))

	globalVars := fiber.Map{
		"siteName": config.SiteName,
		"baseURL":  config.BaseURL,
	}
	if config.Captcha.Provider == "turnstile" {
		globalVars["turnstileSiteKey"] = config.Captcha.Turnstile.SiteKey
		globalVars["turnstileSecretKey"] = config.Captcha.Turnstile.SecretKey
	}

	htmlEngine := mustInitHtmlEngine(config.TemplateDir)
	mail.Initialize(htmlEngine, globalVars)
	mailSender := mustInitMailSender(config.Mail)
	query.SetDefault(mustInitDatabase(config.MySQL))
	captcha.InitVerifier(mustInitCaptchaVerifier(config.Captcha))

	// initialize storage
	redisStorage := redis.New(redis.Config{URL: config.RedisURL})
	cacheStorage := store.NewRedisStorage(redisStorage.Conn())

	// repositories
	var (
		userRepo        = users.NewUserRepository(query.Q)
		pendingUserRepo = users.NewPendingUserRepository(query.Q)
		userOAuthRepo   = users.NewUserOAuthRepository(query.Q)
		userFactorRepo  = users.NewUserFactorRepository(query.Q)
		serviceRepo     = auth.NewServiceRepository(query.Q)
	)

	// services
	var (
		userService      = users.NewUserService(userRepo, userOAuthRepo, userFactorRepo, pendingUserRepo)
		authorizeService = auth.NewAuthorizeService(cacheStorage, serviceRepo)
		twoFactorService = twofactor.NewTwoFactorService(cacheStorage, userFactorRepo, config.MasterKey)
	)

	// middlewares and dependencies
	var (
		oauthProviders = mustInitOAuthProviders(config)
		sessionStore   = session.New(session.Config{
			Storage:        common.NewKVStorage(redisStorage, params.SessionKeyPrefix),
			Expiration:     config.Session.SessionMaxAge,
			CookieSecure:   config.Session.CookieSecure,
			CookieHTTPOnly: config.Session.CookieHttpOnly,
			KeyLookup:      fmt.Sprintf("cookie:%s", config.Session.CookieName),
			KeyGenerator:   sessions.GenerateSessionID,
		})
	)

	// handlers
	var (
		authHandler            = handlers.NewAuthHandler(authorizeService, userService, twoFactorService)
		loginHandler           = handlers.NewLoginHandler(userService, twoFactorService, oauthProviders)
		registerHandler        = handlers.NewRegisterHandler(userService, mailSender)
		oauthHandler           = handlers.NewOAuthHandler(userService, oauthProviders)
		twofactorHandler       = handlers.NewTwoFactorHandler(twoFactorService, userService, mailSender)
		resetPasswordHandler   = handlers.NewResetPasswordHandler(userService, twoFactorService, mailSender)
		accountSettingsHandler = handlers.NewAccountSettingsHandler(userService, twoFactorService, mailSender)
	)

	router := fiber.New(fiber.Config{
		Prefork:       false,
		CaseSensitive: true,
		BodyLimit:     params.ServerBodyLimit,
		IdleTimeout:   params.ServerIdleTimeout,
		ReadTimeout:   params.ServerReadTimeout,
		WriteTimeout:  params.ServerWriteTimeout,
		Views:         htmlEngine,
		ErrorHandler:  middlewares.ErrorHandler,
	})

	router.Use(recover.New())
	router.Use(cors.New(cors.Config{
		AllowOrigins: strings.Join(config.AllowOrigins, ", "),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))
	router.Use(middlewares.GlobalVars(globalVars))
	router.Static("/static", config.StaticDir)
	router.Get("/livez", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	router.Get("/serviceValidate", authHandler.GetServiceValidate)
	router.Get("/p3/serviceValidate", authHandler.GetServiceValidate)

	router.Use(sessions.New(sessionStore))
	router.Get("/", authHandler.GetHome)
	router.Get("/profile", authHandler.GetProfile)
	router.Post("/logout", loginHandler.PostLogout)
	router.Get("/oauth/:provider/callback", oauthHandler.GetOAuthCallback)
	router.Get("/register/verify", registerHandler.GetRegisterVerify)

	router.Use(csrf.New(csrf.Config{}))
	router.Get("/authorize", authHandler.GetAuthorize)
	router.Post("/authorize", authHandler.PostAuthorize)
	router.Get("/login", loginHandler.GetLogin)
	router.Post("/login", loginHandler.PostLogin)
	router.Get("/register", registerHandler.GetRegister)
	router.Post("/register", registerHandler.PostRegister)
	router.Get("/register/oauth", registerHandler.GetRegisterWithOAuth)
	router.Post("/register/oauth", registerHandler.PostRegisterWithOAuth)
	router.Get("/reset-password", resetPasswordHandler.GetResetPassword)
	router.Post("/reset-password", resetPasswordHandler.PostResetPassword)
	router.Get("/forgot-password", resetPasswordHandler.GetForogtPassword)
	router.Post("/forgot-password", resetPasswordHandler.PostForgotPassword)
	router.Get("/2fa/challenge", twofactorHandler.GetChallenge)
	router.Post("/2fa/challenge", twofactorHandler.PostChallenge)
	router.Get("/2fa/otp/verify", twofactorHandler.GetVerifyOTP)
	router.Post("/2fa/otp/verify", twofactorHandler.PostVerifyOTP)
	router.Get("/2fa/totp/enroll", twofactorHandler.GetTOTPEnroll)
	router.Post("/2fa/totp/enroll", twofactorHandler.PostTOTPEnroll)
	router.Get("/2fa/totp/verify", twofactorHandler.GetTOTVerify)
	router.Post("/2fa/totp/verify", twofactorHandler.PostTOTPVerify)
	router.Get("/2fa/settings", twofactorHandler.GetTwoFASettings)
	router.Post("/2fa/settings", twofactorHandler.PostTwoFASettings)
	router.Get("/account/change-password", accountSettingsHandler.GetChangePassword)
	router.Post("/account/change-password", accountSettingsHandler.PostChangePassword)

	return router.Listen(config.ListenAddr)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
