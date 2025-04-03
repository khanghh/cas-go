package config

import (
	"github.com/spf13/viper"
)

const (
	DefaultListenAddr = ":3000"
	DefaultStaticDir  = "./static"
)

type MysqlConfig struct {
	ConnStr         string `yaml:"connStr"`
	MaxIdleConns    int    `yaml:"maxIdleConns"`
	MaxOpenConns    int    `yaml:"maxOpenConns"`
	ConnMaxIdleTime int    `yaml:"connMaxIdleTime"`
	ConnMaxLifetime int    `yaml:"connMaxLifetime"`
}

type ServerConfig struct {
	ListenAddr   string   `yaml:"listenAddr"`
	StaticDir    string   `yaml:"staticDir"`
	TemplateDir  string   `yaml:"templateDir"`
	AllowOrigins []string `yaml:"allowOrigins"`
}

type Config struct {
	Debug  bool         `yaml:"debug"`
	Server ServerConfig `yaml:"server"`
	Mysql  MysqlConfig  `yaml:"mysql"`
}

func (c *Config) Sanitize() error {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = DefaultListenAddr
	}
	if c.Server.StaticDir == "" {
		c.Server.StaticDir = DefaultStaticDir
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
