package twofactor

import (
	"fmt"
	"testing"
	"time"

	"github.com/gofiber/storage/redis/v3"
	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

func TestXxx(t *testing.T) {
	redisURL := "redis://localhost:6379/0"
	redisStorage := redis.New(redis.Config{URL: redisURL})
	store := store.NewRedisStore[UserState](redisStorage.Conn(), params.UserStateStoreKeyPrefix)
	_ = newUserStateStore(store)

	until := time.Now().Add(5 * time.Minute)
	fmt.Println(until.UTC())
	fmt.Println(time.Until(until))
	fmt.Println(time.Until(until.Local()))

	// err := userStateStore.SetAttr(context.Background(), "1", "lock_reason", "", "lock_until", until)
	// if err != nil {
	// 	panic(err)
	// }

	// err = userStateStore.GetAttr(context.Background(), "1", "lock_until", &until)
	// if err != nil {
	// 	panic(err)
	// }
}
