package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/memory/v2"
	"github.com/gofiber/storage/redis/v3"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/common"
	"github.com/khanghh/cas-go/internal/config"
	"github.com/khanghh/cas-go/internal/handlers"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/internal/user"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"github.com/khanghh/cas-go/params"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

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

func mustInitDatabase(dbConfig config.DatabaseConfig) *gorm.DB {
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

func mustInitCacheStorage(config *config.Config) fiber.Storage {
	if config.RedisUrl != "" {
		return redis.New(redis.Config{URL: config.RedisUrl})
	} else {
		return memory.New(memory.Config{GCInterval: 10 * time.Second})
	}
}

func mustInitOAuthProviders(config *config.Config) []oauth.OAuthProvider {
	var providers []oauth.OAuthProvider
	for providerName, providerCfg := range config.AuthProviders.OAuth {
		if providerName == "google" {
			provider := oauth.NewGoogleOauthProvider(providerName, providerCfg.ClientId, providerCfg.ClientSecret)
			providers = append(providers, provider)
		} else {
			slog.Error("Unsupported OAuth provider", "provider", providerName)
			os.Exit(1)
		}
	}
	return providers
}

func run(ctx *cli.Context) error {
	config, err := config.LoadConfig(ctx.String(configFileFlag.Name))
	if err != nil {
		slog.Error("Could not load config file.", "error", err)
		return err
	}

	mustInitLogger(config.Debug || ctx.IsSet(debugFlag.Name))

	query.SetDefault(mustInitDatabase(config.Database))

	cacheStorage := mustInitCacheStorage(config)
	ticketStorage := common.NewKVStorage(cacheStorage, params.TicketStorageKeyPrefix)
	sessionStorage := common.NewKVStorage(cacheStorage, params.SessionStorageKeyPrefix)

	ticketStore := auth.NewTicketStore(ticketStorage)
	sessionStore := session.New(session.Config{
		Storage:        sessionStorage,
		Expiration:     config.Session.SessionMaxAge,
		CookieSecure:   config.Session.CookieSecure,
		CookieHTTPOnly: config.Session.CookieHttpOnly,
		CookieSameSite: config.Session.CookieSameSite,
		KeyLookup:      fmt.Sprintf("cookie:%s", config.Session.CookieName),
		KeyGenerator:   sessions.GenerateSessionID,
	})

	// repositories and dependencies
	var (
		userRepo       = repository.NewUserRepository(query.Q)
		oauthRepo      = repository.NewOAuthRepository(query.Q)
		serviceRepo    = repository.NewServiceRepository(query.Q)
		tokenRepo      = repository.NewTokenRepository(query.Q)
		oauthProviders = mustInitOAuthProviders(config)
	)

	// services
	var (
		userService      = user.NewUserService(userRepo)
		serviceRegistry  = auth.NewServiceRegistry(serviceRepo)
		authorizeService = auth.NewAuthorizeService(ticketStore, serviceRepo, tokenRepo)
		oauthService     = oauth.NewOAuthService(userRepo, oauthRepo, oauthProviders)
	)

	// middlewares and handlers
	var (
		withSession = sessions.WithSessionMiddleware(sessionStore)
		authHandler = handlers.NewAuthHandler(serviceRegistry, authorizeService, userService, oauthService)
	)

	router := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
		BodyLimit:     params.ServerBodyLimit,
		IdleTimeout:   params.ServerIdleTimeout,
		ReadTimeout:   params.ServerReadTimeout,
		WriteTimeout:  params.ServerWriteTimeout,
		Views:         render.NewHtmlEngine(config.TemplateDir),
	})

	router.Use(cors.New(cors.Config{
		AllowOrigins: strings.Join(config.AllowOrigins, ", "),
	}))
	router.Static("/static/*", config.StaticDir)
	router.Get("/login", withSession(authHandler.GetLogin))
	router.Post("/login", withSession(authHandler.PostLogin))
	router.Post("/logout", withSession(authHandler.PostLogout))
	router.Get("/oauth/:provider/callback", withSession(authHandler.GetOAuthCallback))

	return router.Listen(config.ListenAddr)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
