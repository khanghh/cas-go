package model

import (
	"time"

	"gorm.io/gorm"
)

// User stores user information
type User struct {
	gorm.Model
	Name          string      `gorm:"uniqueIndex;size:32;not null"`
	DisplayName   string      `gorm:"size:64;not null"`
	Email         string      `gorm:"uniqueIndex;size:256;not null"`
	EmailVerified bool        `gorm:"default:false;not null"`
	Password      string      `gorm:"size:64;not null"`
	Disabled      bool        `gorm:"default:false;not null"`
	LastLoginAt   *time.Time  `gorm:"index"`
	OAuths        []UserOAuth `gorm:"foreignKey:UserId;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}
