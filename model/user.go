package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username      string     `gorm:"uniqueIndex;size:32"`
	DisplayName   string     `gorm:"size:64"`
	Email         string     `gorm:"uniqueIndex;size:256"`
	EmailVerified bool       `gorm:"default:false"`
	Password      string     `gorm:"size:64;no null"`
	Disabled      bool       `gorm:"default:false"`
	LastLoginAt   *time.Time `gorm:""`
}
