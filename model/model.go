package model

import (
	"github.com/bwmarrin/snowflake"
	"gorm.io/gorm"
)

var snowflakeNode *snowflake.Node

var Models = []interface{}{
	&User{}, &UserOAuth{}, &Service{}, &Token{}, &PendingUser{}, &UserFactor{},
}

func init() {
	var err error
	snowflakeNode, err = snowflake.NewNode(1)
	if err != nil {
		panic(err)
	}
}

func GenerateID() uint {
	return uint(snowflakeNode.Generate())
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(Models...)
}
