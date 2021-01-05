package main

import (
	"context"
	"fmt"
	"net/http"
	"encoding/base64"
	"strings"
)

func init() {
	fmt.Println("serverPlugin plugin is loaded!")
}

func main() {}

// HandlerRegisterer is the name of the symbol krakend looks up to try and register plugins
var HandlerRegisterer registrable = registrable("serverPlugin")

type registrable string

const pluginName = "serverPlugin"

func (r registrable) RegisterHandlers(f func(
	name string,
	handler func(
		context.Context,
		map[string]interface{},
		http.Handler) (http.Handler, error),
)) {
	f(pluginName, r.registerHandlers)
}

func (r registrable) registerHandlers(ctx context.Context, extra map[string]interface{}, handler http.Handler) (http.Handler, error) {

	fmt.Println("server plugin is registered!")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Validate Basic Auth
        auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		r2 := new(http.Request)
		*r2 = *r

		fmt.Println("server plugin is running: ",auth)

		if auth[0] == "Bearer" {
			// Bearer Token for next calls
			payload, _ := base64.StdEncoding.DecodeString(auth[1])
			r2.Header.Set("cookie",string(payload))
			fmt.Println("server plugin is setting cookie: ",auth[1])
		}

		fmt.Println("server plugin is forwarding!")
		handler.ServeHTTP(w, r2)

	}), nil
}