package model

import "gorm.io/gorm"

// UserOAuth stores oauth linking information of a user
type UserOAuth struct {
	gorm.Model
	OAuthId  string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	UserId   uint   `gorm:"not null;index:idx_user_oauth,unique"`
	Provider string `gorm:"size:32;not null;index:idx_user_oauth,unique"`
	Email    string `gorm:"size:256;not null"`
	Name     string `gorm:"size:256;not null"`
	Picture  string `gorm:"size:256;not null"`
}

func (UserOAuth) TableName() string {
	return "user_oauths"
}
