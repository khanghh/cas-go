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

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	Timeout  int    `yaml:"timeout"`
	TLS      bool   `yaml:"tls"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type MailConfig struct {
	Backend    string     `yaml:"backend"`
	SMTPConfig SMTPConfig `yaml:"smtp"`
}

type Config struct {
	Debug         bool          `yaml:"debug"`
	SiteName      string        `yaml:"siteName"`
	BaseURL       string        `yaml:"baseURL"`
	MasterKey     string        `yaml:"masterKey"`
	ListenAddr    string        `yaml:"listenAddr"`
	StaticDir     string        `yaml:"staticDir"`
	TemplateDir   string        `yaml:"templateDir"`
	AllowOrigins  []string      `yaml:"allowOrigins"`
	RedisURL      string        `yaml:"redisURL"`
	Session       SessionConfig `yaml:"session"`
	MySQL         MySQLConfig   `yaml:"mysql"`
	Mail          MailConfig    `yaml:"mail"`
	AuthProviders struct {
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
