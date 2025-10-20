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
	Dsn             string `mapstructure:"dsn"`
	TablePrefix     string `mapstructure:"tablePrefix"`
	MaxIdleConns    int    `mapstructure:"maxIdleConns"`
	MaxOpenConns    int    `mapstructure:"maxOpenConns"`
	ConnMaxIdleTime int    `mapstructure:"connMaxIdleTime"`
	ConnMaxLifetime int    `mapstructure:"connMaxLifetime"`
}

type SessionConfig struct {
	SessionMaxAge  time.Duration `mapstructure:"sessionMaxAge"`
	CookieName     string        `mapstructure:"cookieName"`
	CookieHttpOnly bool          `mapstructure:"cookieHttpOnly"`
	CookieSecure   bool          `mapstructure:"cookieSecure"`
}

type LdapConfig struct {
	Address  string `mapstructure:"address"`
	BaseDN   string `mapstructure:"baseDN"`
	Password string `mapstructure:"password"`
}

type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"clientID"`
	ClientSecret string   `mapstructure:"clientSecret"`
	Scope        []string `mapstructure:"scope"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	TLS      bool   `mapstructure:"tls"`
	CertFile string `mapstructure:"certFile"`
	KeyFile  string `mapstructure:"keyFile"`
	CAFile   string `mapstructure:"caFile"`
}

type MailConfig struct {
	Backend string     `mapstructure:"backend"`
	SMTP    SMTPConfig `mapstructure:"smtp"`
}

type TurnstileConfig struct {
	SiteKey   string `mapstructure:"siteKey"`
	SecretKey string `mapstructure:"secretKey"`
}

type CaptchaConfig struct {
	Provider  string          `mapstructure:"provider"`
	Turnstile TurnstileConfig `mapstructure:"turnstile,omitempty"`
}

type RedisConfig struct {
	URL         string `mapstructure:"url"`
	PoolSize    int    `mapstructure:"poolSize"`
	ClusterMode bool   `mapstructure:"clusterMode"`
}

type Config struct {
	Debug         bool          `mapstructure:"debug"`
	SiteName      string        `mapstructure:"siteName"`
	BaseURL       string        `mapstructure:"baseURL"`
	MasterKey     string        `mapstructure:"masterKey"`
	ListenAddr    string        `mapstructure:"listenAddr"`
	StaticDir     string        `mapstructure:"staticDir"`
	TemplateDir   string        `mapstructure:"templateDir"`
	AllowOrigins  []string      `mapstructure:"allowOrigins"`
	Redis         RedisConfig   `mapstructure:"redis"`
	Session       SessionConfig `mapstructure:"session"`
	Mail          MailConfig    `mapstructure:"mail"`
	MySQL         MySQLConfig   `mapstructure:"mysql"`
	AuthProviders struct {
		OAuth map[string]OAuthProviderConfig `mapstructure:"oauth"`
		Ldap  LdapConfig                     `mapstructure:"ldap"`
	} `mapstructure:"authProviders"`
	Captcha CaptchaConfig `mapstructure:"captcha"`
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

	viper.AutomaticEnv()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	if err := config.Sanitize(); err != nil {
		return nil, err
	}
	return &config, nil
}
