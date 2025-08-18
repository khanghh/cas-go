package model

import "gorm.io/gorm"

// UserOAuth stores oauth linking information of a user
type UserOAuth struct {
	gorm.Model
	UserID      uint   `gorm:"default:null"`
	Provider    string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	ProfileID   string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	Email       string `gorm:"size:256;not null"`
	DisplayName string `gorm:"size:256;not null"`
	Picture     string `gorm:"size:256;not null"`
}

func (UserOAuth) TableName() string {
	return "user_oauths"
}

func (u *UserOAuth) BeforeCreate(tx *gorm.DB) error {
	u.ID = GenerateID()
	return nil
}
