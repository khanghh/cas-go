package model

import (
	"gorm.io/gorm"
)

type Service struct {
	gorm.Model
	DisplayName  string `gorm:"size:128;not null"`
	ClientId     string `gorm:"size:128;uniqueIndex;not null"`
	ClientSecret string `gorm:"size:128;not null"`
	ServiceUrl   string `gorm:"size:1024;not null"`
	CallbackUrl  string `gorm:"size:1024;not null"`
}
