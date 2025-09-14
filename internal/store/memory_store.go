package store

import (
	"bytes"
	"context"
	"encoding/gob"
	"time"

	"github.com/gofiber/storage/memory/v2"
)

type MemoryStore[T any] struct {
	storage *memory.Storage
}

func (s *MemoryStore[T]) Get(ctx context.Context, key string) (*T, error) {
	blob, err := s.storage.Get(key)
	if err != nil {
		return nil, err
	}

	var obj T
	err = gob.NewDecoder(bytes.NewReader(blob)).Decode(&obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

func (s *MemoryStore[T]) Set(ctx context.Context, key string, val T, expiresIn time.Duration) error {
	blob := new(bytes.Buffer)
	if err := gob.NewEncoder(blob).Encode(val); err != nil {
		return err
	}
	return s.storage.Set(key, blob.Bytes(), expiresIn)
}

func (s *MemoryStore[T]) Save(ctx context.Context, key string, val T) error {
	blob := new(bytes.Buffer)
	if err := gob.NewEncoder(blob).Encode(val); err != nil {
		return err
	}
	return s.storage.Set(key, blob.Bytes(), 0)
}

func (s *MemoryStore[T]) Del(ctx context.Context, key string) error {
	return s.storage.Delete(key)
}

func (s *MemoryStore[T]) SetAttr(ctx context.Context, key string, field string, val any) error {
	panic("TODO: Implement")

}

func (s *MemoryStore[T]) GetAttr(ctx context.Context, key string, field string, val any) error {
	panic("TODO: Implement")
}

func (s *MemoryStore[T]) IncrAttr(ctx context.Context, key string, field string, delta int64) (int64, error) {
	panic("TODO: Implement")
}

func NewMemoryStore[T any]() *MemoryStore[T] {
	return &MemoryStore[T]{
		storage: memory.New(memory.Config{GCInterval: 10 * time.Second}),
	}
}
