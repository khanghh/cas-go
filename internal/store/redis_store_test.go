package store

import (
	"context"
	"fmt"
	"testing"

	fredis "github.com/gofiber/storage/redis/v3"
)

func TestSetPerson(t *testing.T) {
	type Person struct {
		Name string `redis:"name"`
		Age  int    `redis:"age"`
	}

	redisURL := "redis://localhost:6379/0"
	storage := fredis.New(fredis.Config{URL: redisURL})
	store := NewRedisStore[Person](storage.Conn(), "person:")

	p := Person{
		Name: "John Doe",
		Age:  30,
	}
	err := store.Set(context.Background(), "1", p, 0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetPerson(t *testing.T) {
	type Person struct {
		Name string `redis:"name"`
		Age  int    `redis:"age"`
	}

	redisURL := "redis://localhost:6379/0"
	storage := fredis.New(fredis.Config{URL: redisURL})
	store := NewRedisStore[Person](storage.Conn(), "person:")

	ctx := context.Background()
	newVal, err := store.IncrAttr(ctx, "1", "age", 2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("newVal: ", newVal)

	var age int
	if err := store.GetAttr(ctx, "1", "age", &age); err != nil {
		t.Fatal(err)
	}
	fmt.Println("age:", age)
}
