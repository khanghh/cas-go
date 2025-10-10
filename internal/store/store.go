package store

import (
	"context"
	"time"
)

type store[T any] struct {
	storage   Storage
	keyPrefix string
}

func (s *store[T]) Get(ctx context.Context, key string) (T, error) {
	var obj T
	err := s.storage.Get(ctx, s.keyPrefix+key, &obj)
	return obj, err
}

func (s *store[T]) Set(ctx context.Context, key string, val T, expiresIn time.Duration) error {
	return s.storage.Set(ctx, s.keyPrefix+key, val, expiresIn)
}

func (s *store[T]) Save(ctx context.Context, key string, val T) error {
	return s.storage.Set(ctx, s.keyPrefix+key, val, -1)
}

func (s *store[T]) Delete(ctx context.Context, key string) error {
	return s.storage.Delete(ctx, s.keyPrefix+key)
}

func (s *store[T]) Remove(ctx context.Context, key string) (*T, error) {
	return nil, nil
}

func (s *store[T]) Expire(ctx context.Context, key string, expiresAt time.Time) error {
	return s.storage.Expire(ctx, s.keyPrefix+key, expiresAt)
}

func (s *store[T]) SetAttr(ctx context.Context, key string, values ...any) error {
	return s.storage.SetAttr(ctx, s.keyPrefix+key, values...)
}

func (s *store[T]) GetAttr(ctx context.Context, key, field string, val any) error {
	return s.storage.GetAttr(ctx, s.keyPrefix+key, field, val)
}

func (s *store[T]) IncrAttr(ctx context.Context, key string, field string, delta int64) (int64, error) {
	return s.storage.IncrAttr(ctx, s.keyPrefix+key, field, delta)
}

func (s *store[T]) ExpireAttr(ctx context.Context, key string, expiresAt time.Time, fields ...string) error {
	return s.storage.ExpireAttr(ctx, s.keyPrefix+key, expiresAt, fields...)
}

func New[T any](storage Storage, keyPrefix string) Store[T] {
	return &store[T]{
		storage:   storage,
		keyPrefix: keyPrefix,
	}
}
