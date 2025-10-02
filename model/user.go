package model

import (
	"time"

	"gorm.io/gorm"
)

// User stores user information
type User struct {
	ID            uint        `gorm:"primarykey"`
	Username      string      `gorm:"uniqueIndex;size:32;not null"  redis:"username"`
	FullName      string      `gorm:"size:64;not null"              redis:"full_name"`
	Email         string      `gorm:"uniqueIndex;size:256;not null" redis:"email"`
	EmailVerified bool        `gorm:"default:false;not null"`
	Password      string      `gorm:"size:64;not null"              redis:"password"`
	Picture       string      `gorm:"size:256;not null"             redis:"picture"`
	Disabled      bool        `gorm:"default:false;not null"`
	OAuths        []UserOAuth `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.ID = GenerateID()
	return nil
}
