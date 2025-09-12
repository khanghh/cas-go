package model

import (
	"time"

	"gorm.io/gorm"
)

type Service struct {
	ID          uint   `gorm:"primarykey"`
	Name        string `gorm:"size:128;not null"`
	CallbackURL string `gorm:"size:1024;not null"`
	AutoLogin   bool   `gorm:"not null;default:false"`
	SigningKey  string `gorm:"size:1024;not null"`
	StripQuery  bool   `gorm:"not null;default:false"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}
