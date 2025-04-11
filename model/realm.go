package model

import "gorm.io/gorm"

type Realm struct {
	gorm.Model
	Name        string `gorm:"size:64;uniqueIndex;not null"`
	DisplayName string `gorm:"size:128"`
}
