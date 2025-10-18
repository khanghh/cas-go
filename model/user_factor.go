package model

import (
	"time"

	"gorm.io/gorm"
)

type UserFactor struct {
	ID        uint   `gorm:"primarykey"`
	UserID    uint   `gorm:"not null;index:idx_user_factor,unique"`
	Type      string `gorm:"size:32;not null;index:idx_user_factor,unique"`
	Secret    string `gorm:"size:128;not null"`
	Enabled   bool   `gorm:"default:false;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
