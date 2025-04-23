package main

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var mu sync.Mutex
var clientLimits = make(map[string]*rate.Limiter)

func getLimiter(clientIP string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := clientLimits[clientIP]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Millisecond*500), 5)
		clientLimits[clientIP] = limiter
	}
	return limiter
}

func CheckCookie(cookie *http.Cookie) error {
	var err error
	if err = cookie.Valid(); err != nil {
		return err
	}
	// NOTE: cookie sent by browser does not include expiry time
	// if cookie.Expires.Before(time.Now()) {
	// 	return errors.New("cookie expired")
	// }
	if cookie.Value == "" {
		return errors.New("cookie has no value")
	}
	return nil
}
