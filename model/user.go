package model

import (
	"time"

	"gorm.io/gorm"
)

// User stores user information
type User struct {
	ID           uint        `gorm:"primarykey"`
	Username     string      `gorm:"uniqueIndex;size:32;not null"`
	FullName     string      `gorm:"size:64;not null"`
	Email        string      `gorm:"uniqueIndex;size:256;not null"`
	Password     string      `gorm:"size:64;not null"`
	Picture      string      `gorm:"size:256;not null"`
	TwoFAEnabled bool        `gorm:"default:false;not null"`
	Disabled     bool        `gorm:"default:false;not null"`
	OAuths       []UserOAuth `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.ID = GenerateID()
	return nil
}
