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
	"github.com/khanghh/cas-go/internal/config"
	"github.com/khanghh/cas-go/internal/handlers"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/repositories"
	"github.com/khanghh/cas-go/internal/services"
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
	app.Usage = "CAS Gateway"
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

func mustInitSessionStorage(config *config.Config) fiber.Storage {
	var storage fiber.Storage
	if config.Session.RedisUrl != "" {
		storage = redis.New(redis.Config{URL: config.Session.RedisUrl})
	} else {
		storage = memory.New(memory.Config{GCInterval: 10 * time.Second})
	}
	return sessions.NewSessionStorage(storage, config.Session.StorageKeyPrefix)
}

func run(ctx *cli.Context) error {
	config, err := config.LoadConfig(ctx.String(configFileFlag.Name))
	if err != nil {
		slog.Error("Could not load config file.", "error", err)
		return err
	}

	mustInitLogger(config.Debug || ctx.IsSet(debugFlag.Name))

	query.SetDefault(mustInitDatabase(config.Database))
	sessionStore := session.New(session.Config{
		Storage:        mustInitSessionStorage(config),
		CookieSecure:   config.Session.CookieSecure,
		CookieHTTPOnly: config.Session.CookieHttpOnly,
		CookieSameSite: config.Session.CookieSameSite,
		KeyLookup:      fmt.Sprintf("cookie:%s", config.Session.CookieName),
		KeyGenerator:   sessions.GenerateSessionID,
	})

	// repositories
	var (
		userRepo = repositories.NewUserRepository(query.Q)
	)

	// services
	var (
		authService = services.NewAuthService(&userRepo)
	)

	// middlewares and handlers
	var (
		withSession = sessions.WithSessionMiddleware(sessionStore)
		authHandler = handlers.NewAuthHandler(authService)
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
	router.Post("/logout", withSession(authHandler.PostLogout))

	return router.Listen(config.ListenAddr)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
