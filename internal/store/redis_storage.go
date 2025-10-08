package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStorage struct {
	rdb redis.UniversalClient
}

func (s *RedisStorage) Get(ctx context.Context, key string, val any) error {
	cmd := s.rdb.HGetAll(ctx, key)
	if len(cmd.Val()) == 0 {
		return ErrNotFound
	}
	return cmd.Scan(val)
}

func (s *RedisStorage) Set(ctx context.Context, key string, val any, expiresIn time.Duration) error {
	if expiresIn == -1 {
		return s.rdb.HSet(ctx, key, val).Err()
	}
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, key, val)
	pipe.Expire(ctx, key, expiresIn)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStorage) Delete(ctx context.Context, key string) error {
	deleted, err := s.rdb.Del(ctx, key).Result()
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *RedisStorage) Expire(ctx context.Context, key string, expiresAt time.Time) error {
	return s.rdb.ExpireAt(ctx, key, expiresAt).Err()
}

func (s *RedisStorage) SetAttr(ctx context.Context, key string, values ...any) error {
	return s.rdb.HSet(ctx, key, values...).Err()
}

func (s *RedisStorage) GetAttr(ctx context.Context, key, field string, val any) error {
	return s.rdb.HGet(ctx, key, field).Scan(val)
}

func (s *RedisStorage) IncrAttr(ctx context.Context, key, field string, delta int64) (int64, error) {
	return s.rdb.HIncrBy(ctx, key, field, delta).Result()
}

func (s *RedisStorage) ExpireAttr(ctx context.Context, key string, expiresAt time.Time, fields ...string) error {
	return s.rdb.HExpireAt(ctx, key, expiresAt, fields...).Err()
}

func NewRedisStorage(db redis.UniversalClient) *RedisStorage {
	return &RedisStorage{
		rdb: db,
	}
}
