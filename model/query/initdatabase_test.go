package query

import (
	"os"
	"testing"

	"github.com/khanghh/cas-go/model"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var db *gorm.DB

func init() {
	connStr := os.Getenv("DB_URL")
	var err error
	db, err = gorm.Open(mysql.Open(connStr), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	if err != nil {
		panic(err)
	}
	SetDefault(db)
}

func TestInitDatabase(t *testing.T) {
	err := Service.Create(&model.Service{
		Name:          "test",
		LoginCallback: "http://localhost:3000/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
}
