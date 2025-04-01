package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/gofiber/fiber"
	"github.com/khanghh/cas-go/params"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
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

type appConfig struct {
	Address string `yaml:"address"`
	Debug   bool   `yaml:"debug"`
}

func init() {
	app = cli.NewApp()
	app.EnableBashCompletion = true
	app.Usage = "Central Authenticate Service"
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

func loadConfig(ctx *cli.Context) (*appConfig, error) {
	configFile := ctx.String(configFileFlag.Name)
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config appConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func initLogger(debug bool) error {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))
	return nil
}

func run(ctx *cli.Context) error {
	config, err := loadConfig(ctx)
	if err != nil {
		slog.Error("Could not load config file.", "error", err)
		return err
	}
	initLogger(config.Debug || ctx.IsSet(debugFlag.Name))

	router := fiber.New()

	slog.Info("Starting CAS sever", "address", config.Address)
	return router.Listen(config.Address)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
