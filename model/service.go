package model

import (
	"gorm.io/gorm"
)

type Service struct {
	gorm.Model
	DisplayName string `gorm:"size:128;not null"`
	ServiceUrl  string `gorm:"size:1024;not null"`
	CallbackUrl string `gorm:"size:1024;not null"`
	AutoLogin   bool   `gorm:"not null;default:false"`
	PublicKey   string `gorm:"size:1024;not null"`
}
