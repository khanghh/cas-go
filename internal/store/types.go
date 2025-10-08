package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
)

type Storage interface {
	Get(ctx context.Context, key string, val any) error
	Set(ctx context.Context, key string, val any, expiresIn time.Duration) error
	Delete(ctx context.Context, key string) error
	Expire(ctx context.Context, key string, expiresAt time.Time) error
	SetAttr(ctx context.Context, key string, values ...any) error
	GetAttr(ctx context.Context, key, field string, val any) error
	IncrAttr(ctx context.Context, key, field string, delta int64) (int64, error)
	ExpireAttr(ctx context.Context, key string, expires time.Time, fields ...string) error
}

type Store[T any] interface {
	Get(ctx context.Context, key string) (*T, error)
	Set(ctx context.Context, key string, val T, expiresIn time.Duration) error
	Save(ctx context.Context, key string, val T) error
	Delete(ctx context.Context, key string) error
	Remove(ctx context.Context, key string) (*T, error)
	Expire(ctx context.Context, key string, expiresAt time.Time) error
	SetAttr(ctx context.Context, key string, values ...any) error
	GetAttr(ctx context.Context, key, field string, val any) error
	IncrAttr(ctx context.Context, key, field string, delta int64) (int64, error)
	ExpireAttr(ctx context.Context, key string, expiresAt time.Time, fields ...string) error
}
