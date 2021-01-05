package main

import (
	"context"
	"fmt"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	//"time"
	"encoding/base64"
	"strings"
	"encoding/json"
)

func init() {
	fmt.Println("login-plugin is loaded!")
}

func main() {}

// HandlerRegisterer is the name of the symbol krakend looks up to try and register plugins
var HandlerRegisterer registrable = registrable("login-plugin")

type registrable string

const outputHeaderName = "X-AUTH-TOKEN"
const pluginName = "login-plugin"

func (r registrable) RegisterHandlers(f func(
	name string,
	handler func(
		context.Context,
		map[string]interface{},
		http.Handler) (http.Handler, error),
)) {
	f(pluginName, r.registerHandlers)
}

type PluginConf struct {
	Path string `json:"path"`
	User string `json:"user"`
	Pass string `json:"pwd"`
	Cookies []string `json:"cookies"`
    Apikeys []TCredential `json:"apiKeys"`
}

type TCredential struct {
	Username string `json:"username"`
    Password string `json:"password"`
}

func validate(pConf PluginConf, username string, password string) bool {
	for _,cred := range pConf.Apikeys {
    	if username == cred.Username && password == cred.Password {
        	return true
		}
	}
    return false
}

func (r registrable) registerHandlers(ctx context.Context, extra map[string]interface{}, handler http.Handler) (http.Handler, error) {
	configfile, ok := extra["conf"].(string)
	if !ok {
		panic(errors.New("incorrect config").Error())
	}
	backendHost, ok := extra["host"].(string)
	if !ok {
		panic(errors.New("incorrect config").Error())
	}

	byteValue, err := ioutil.ReadFile(configfile)
	if err != nil {
		panic(errors.New("incorrect config file").Error())
	}

	var pluginConf PluginConf

	json.Unmarshal(byteValue, &pluginConf)

	//fmt.Println("PluginConf: ", pluginConf)

	fmt.Println("login-plugin is registered!")

	//client := &http.Client{Timeout: 3 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Validate Basic Auth
        auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		r2 := new(http.Request)
		*r2 = *r

		if auth[0] == "Bearer" {
			// Bearer Token for next calls
			payload, _ := base64.StdEncoding.DecodeString(auth[1])
			r2.Header.Set("cookie",string(payload))
		}

		if auth[0] == "Basic" {
			// Basic Auth for initial token
			payload, _ := base64.StdEncoding.DecodeString(auth[1])
			pair := strings.SplitN(string(payload), ":", 2)

			if len(pair) != 2 || !validate(pluginConf, pair[0], pair[1]) {
				http.Error(w, "authorization failed", http.StatusUnauthorized)
				return
			}

			// Auth ready now create session
			rs, err := http.PostForm(backendHost+pluginConf.Path, url.Values{
				"_username": { pluginConf.User },
				"_password": { pluginConf.Pass },
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotAcceptable)
				return
			}
			defer rs.Body.Close()

			jwtToken := ""
			for _, cookie := range rs.Cookies() {
				for _, cname := range pluginConf.Cookies {
					if cookie.Name == cname {
						r2.AddCookie(cookie)
						jwtToken += base64.StdEncoding.EncodeToString([]byte(cookie.Raw))
						http.SetCookie(w,cookie)
					}
				}
			}
			w.Header().Set(outputHeaderName,jwtToken)
			fmt.Fprintf(w, "{ \"message\": \"")
			handler.ServeHTTP(w, r2)
			fmt.Fprintf(w, "\"}")

		} else {
			// Do nothing
			handler.ServeHTTP(w, r)
		}

	}), nil
}