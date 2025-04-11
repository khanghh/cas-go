package model

import (
	"gorm.io/gorm"
)

type Token struct {
	gorm.Model
	Code         string `gorm:"size:32;not null"`
	User         string `gorm:"size:32l;not null"`
	Realm        string `gorm:"size:32l;not null"`
	AccessToken  string `gorm:"size:512;not null"`
	RefreshToken string `gorm:"size:512;not null"`
	Scope        string `gorm:"default:read"`
	ExpireIn     int64  `gorm:"default:0"` // duration in seconds
	Type         string `gorm:"not null"`
	Revoked      bool   `gorm:"default:false"`
}
