package common

import (
	"context"
	"net/http"

	"github.com/khanghh/cas-go/params"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func StartHealthCheckServer(ctx context.Context, done chan struct{}, rdb redis.UniversalClient, db *gorm.DB) {
	mux := http.NewServeMux()

	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		sqlDB, err := db.DB()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		if err := sqlDB.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		if _, err := rdb.Ping(r.Context()).Result(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:    params.HealthCheckServerAddr,
		Handler: mux,
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		close(done)
	case <-serverErr:
		close(done)
	}
}
