package model

import (
	"gorm.io/gorm"
)

type Service struct {
	gorm.Model
	Name        string `gorm:"size:128;not null"`
	CallbackURL string `gorm:"size:1024;not null"`
	AutoLogin   bool   `gorm:"not null;default:false"`
	PublicKey   string `gorm:"size:1024;not null"`
	StripQuery  bool   `gorm:"not null;default:false"`
}
