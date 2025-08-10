package config

import (
	"time"

	"github.com/khanghh/cas-go/params"
	"github.com/spf13/viper"
)

const (
	DefaultListenAddr   = ":3000"
	DefaultStaticDir    = "./static"
	DefaultCookieMaxAge = 7 * 24 * time.Hour
)

type MySQLConfig struct {
	Dsn             string `yaml:"dsn"`
	TablePrefix     string `yaml:"tablePrefix"`
	MaxIdleConns    int    `yaml:"maxIdleConns"`
	MaxOpenConns    int    `yaml:"maxOpenConns"`
	ConnMaxIdleTime int    `yaml:"connMaxIdleTime"`
	ConnMaxLifetime int    `yaml:"connMaxLifetime"`
}

type SessionConfig struct {
	SessionMaxAge  time.Duration `yaml:"sessionMaxAge"`
	CookieName     string        `yaml:"cookieName"`
	CookieHttpOnly bool          `yaml:"cookieHttpOnly"`
	CookieSecure   bool          `yaml:"cookieSecure"`
}

type LdapConfig struct {
	Address  string `yaml:"address"`
	BaseDn   string `yaml:"baseDn"`
	Password string `yaml:"password"`
}

type OAuthProviderConfig struct {
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	Scope        []string `yaml:"scope"`
}

type Config struct {
	Debug              bool          `yaml:"debug"`
	AppName            string        `yaml:"appName"`
	BaseURL            string        `yaml:"baseURL"`
	ListenAddr         string        `yaml:"listenAddr"`
	StaticDir          string        `yaml:"staticDir"`
	TemplateDir        string        `yaml:"templateDir"`
	AllowOrigins       []string      `yaml:"allowOrigins"`
	RedisURL           string        `yaml:"redisURL"`
	Session            SessionConfig `yaml:"session"`
	MySQL              MySQLConfig   `yaml:"mysql"`
	StateEncryptionKey string        `yaml:"stateEncryptionKey"`
	AuthProviders      struct {
		OAuth map[string]OAuthProviderConfig `yaml:"oauth"`
		Ldap  LdapConfig                     `yaml:"ldap"`
	} `yaml:"authProviders"`
}

func (c *Config) Sanitize() error {
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.StaticDir == "" {
		c.StaticDir = DefaultStaticDir
	}
	if c.Session.SessionMaxAge == 0 {
		c.Session.SessionMaxAge = DefaultCookieMaxAge
	}

	if c.StateEncryptionKey == "" {
		c.StateEncryptionKey = params.DefaultStateEncryptionKey
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
