package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore[T any] struct {
	rdb       redis.UniversalClient
	keyPrefix string
}

func (s *RedisStore[T]) Get(ctx context.Context, key string) (*T, error) {
	cmd := s.rdb.HGetAll(ctx, s.keyPrefix+key)
	if len(cmd.Val()) == 0 {
		return nil, ErrNotFound
	}
	var obj T
	if err := cmd.Scan(&obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

func (s *RedisStore[T]) Set(ctx context.Context, key string, val T, expiresIn time.Duration) error {
	if expiresIn == 0 {
		return s.Save(ctx, key, val)
	}
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, s.keyPrefix+key, val)
	pipe.Expire(ctx, s.keyPrefix+key, expiresIn)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStore[T]) Save(ctx context.Context, key string, val T) error {
	return s.rdb.HSet(ctx, s.keyPrefix+key, val).Err()
}

func (s *RedisStore[T]) Del(ctx context.Context, key string) error {
	err := s.rdb.Del(ctx, s.keyPrefix+key).Err()
	return err
}

func (s *RedisStore[T]) SetAttr(ctx context.Context, key string, values ...any) error {
	return s.rdb.HSet(ctx, s.keyPrefix+key, values...).Err()
}

func (s *RedisStore[T]) GetAttr(ctx context.Context, key, field string, val any) error {
	return s.rdb.HGet(ctx, s.keyPrefix+key, field).Scan(val)
}

func (s *RedisStore[T]) IncrAttr(ctx context.Context, key, field string, delta int64) (int64, error) {
	return s.rdb.HIncrBy(ctx, s.keyPrefix+key, field, delta).Result()
}

func (s *RedisStore[T]) AttrExpire(ctx context.Context, key string, expiresIn time.Duration, fields ...string) error {
	return s.rdb.HExpire(ctx, s.keyPrefix+key, expiresIn, fields...).Err()
}

func NewRedisStore[T any](db redis.UniversalClient, keyPrefix string) *RedisStore[T] {
	return &RedisStore[T]{
		rdb:       db,
		keyPrefix: keyPrefix,
	}
}
