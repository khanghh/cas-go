package model

import (
	"time"

	"gorm.io/gorm"
)

type PendingUser struct {
	ID          uint   `gorm:"primarykey"`
	Username    string `gorm:"size:32;not null"`
	FullName    string `gorm:"size:64;not null"`
	Email       string `gorm:"size:256;not null"`
	Password    string `gorm:"size:64;not null"`
	Picture     string `gorm:"size:256;not null"`
	ActiveToken string `gorm:"size:256;not null"`
	Approved    bool   `gorm:"default:false;not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}
