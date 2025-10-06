package model

import (
	"time"

	"gorm.io/gorm"
)

// UserOAuth stores oauth linking information of a user
type UserOAuth struct {
	ID          uint   `gorm:"primarykey"`
	UserID      uint   `gorm:"default:null"`
	Provider    string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	ProfileID   string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	Email       string `gorm:"size:256;not null"`
	DisplayName string `gorm:"size:256;not null"`
	Picture     string `gorm:"size:256;not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (UserOAuth) TableName() string {
	return "user_oauth"
}

func (u *UserOAuth) BeforeCreate(tx *gorm.DB) error {
	u.ID = GenerateID()
	return nil
}
