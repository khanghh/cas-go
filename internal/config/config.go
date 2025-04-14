package config

import (
	"time"

	"github.com/spf13/viper"
)

const (
	DefaultListenAddr   = ":3000"
	DefaultStaticDir    = "./static"
	DefaultCookieMaxAge = 7 * 24 * time.Hour
)

type DatabaseConfig struct {
	Dsn             string `yaml:"dsn"`
	TablePrefix     string `yaml:"tablePrefix"`
	MaxIdleConns    int    `yaml:"maxIdleConns"`
	MaxOpenConns    int    `yaml:"maxOpenConns"`
	ConnMaxIdleTime int    `yaml:"connMaxIdleTime"`
	ConnMaxLifetime int    `yaml:"connMaxLifetime"`
}

type SessionConfig struct {
	CookieName       string        `yaml:"cookieName"`
	CookieMaxAge     time.Duration `yaml:"cookieMaxAge"`
	CookieSecure     bool          `yaml:"cookieSecure"`
	CookieHttpOnly   bool          `yaml:"cookieHttpOnly"`
	CookieSameSite   string        `yaml:"cookieSameSite"`
	StorageKeyPrefix string        `yaml:"storageKeyPrefix"`
	RedisUrl         string        `yaml:"redisUrl"`
}

type Config struct {
	Debug        bool           `yaml:"debug"`
	ListenAddr   string         `yaml:"listenAddr"`
	StaticDir    string         `yaml:"staticDir"`
	TemplateDir  string         `yaml:"templateDir"`
	AllowOrigins []string       `yaml:"allowOrigins"`
	Session      SessionConfig  `yaml:"session"`
	Database     DatabaseConfig `yaml:"database"`
}

func (c *Config) Sanitize() error {
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.StaticDir == "" {
		c.StaticDir = DefaultStaticDir
	}
	if c.Session.CookieMaxAge == 0 {
		c.Session.CookieMaxAge = DefaultCookieMaxAge
	}
	if c.Session.CookieSameSite == "" {
		c.Session.CookieSameSite = "Strict"
	}
	return nil
}

func LoadConfig(filename string) (*Config, error) {
	viper.SetConfigFile(filename)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	if err := config.Sanitize(); err != nil {
		return nil, err
	}
	return &config, nil
}
