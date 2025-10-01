package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
)

type Store[T any] interface {
	Get(ctx context.Context, key string) (*T, error)
	Set(ctx context.Context, key string, val T, expiresIn time.Duration) error
	Save(ctx context.Context, key string, val T) error
	Del(ctx context.Context, key string) error
	SetAttr(ctx context.Context, key string, values ...any) error
	GetAttr(ctx context.Context, key, field string, val any) error
	IncrAttr(ctx context.Context, key, field string, delta int64) (int64, error)
	AttrExpire(ctx context.Context, key string, expiresIn time.Duration, fields ...string) error
}
