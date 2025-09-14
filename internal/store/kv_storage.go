package store

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

type KVStorage struct {
	fiber.Storage
	keyPrefix string
}

func (s *KVStorage) Get(key string) ([]byte, error) {
	return s.Storage.Get(s.keyPrefix + key)
}

func (s *KVStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.Storage.Set(s.keyPrefix+key, val, exp)
}

func (s *KVStorage) Delete(key string) error {
	return s.Storage.Delete(s.keyPrefix + key)
}

func NewKVStorage(storage fiber.Storage, keyPrefix string) fiber.Storage {
	return &KVStorage{
		Storage:   storage,
		keyPrefix: keyPrefix,
	}
}
