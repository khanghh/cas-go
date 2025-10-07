package model

import (
	"time"

	"gorm.io/gorm"
)

type Service struct {
	ID             uint   `gorm:"primarykey"`
	Name           string `gorm:"size:128;not null"`
	LoginCallback  string `gorm:"size:1024;not null"`
	LogoutCallback string `gorm:"size:1024;not null"`
	StripQuery     bool   `gorm:"not null;default:false"`
	AutoLogin      bool   `gorm:"not null;default:false"`
	SigningKey     string `gorm:"size:1024;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}
