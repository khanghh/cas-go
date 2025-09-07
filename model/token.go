package model

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	ID           uint   `gorm:"primarykey"`
	Code         string `gorm:"size:32;not null"`
	User         string `gorm:"size:32;not null"`
	Realm        string `gorm:"size:32;not null"`
	AccessToken  string `gorm:"size:512;not null"`
	RefreshToken string `gorm:"size:512;not null"`
	Scope        string `gorm:"not null"`  // service url that the token was authorized
	ExpireIn     int64  `gorm:"default:0"` // duration in seconds
	Type         string `gorm:"not null"`
	Revoked      bool   `gorm:"default:false"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}
