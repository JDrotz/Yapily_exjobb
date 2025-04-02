package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Institutions struct {
	data []Institution
}

type Institution struct {
	id int
}

func main() {
	institutions, err := get_institutions()
	if err != nil {
		return
	}
	_ = institutions
}

func get_institutions() (*Institutions, error) {
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return nil, err
	}
	var userInfo = req.URL.User.Password()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	jsonBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println(jsonBody)
	return nil, nil
}
