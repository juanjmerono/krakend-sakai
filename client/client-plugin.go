package main

import (
	"context"
	"fmt"
	"errors"
	"io/ioutil"
	"net/http"
	"time"
	"encoding/base64"
	"strings"
	"encoding/json"
)

// ClientRegisterer is the symbol the plugin loader will try to load. It must implement the RegisterClient interface
var ClientRegisterer = registerer("clientPlugin")

type registerer string

func (r registerer) RegisterClients(f func(
	name string,
	handler func(context.Context, map[string]interface{}) (http.Handler, error),
)) {
	f(string(r), r.registerClients)
}

func init() {
	fmt.Println("krakend-example client plugin loaded!!!")
}

func main() {}

type PluginConf struct {
	Posturl string `json:"postURL"`
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


func (r registerer) registerClients(ctx context.Context, extra map[string]interface{}) (http.Handler, error) {
	configfile, ok := extra["conf"].(string)
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

	fmt.Println("client plugin is registered!")

	client := &http.Client{Timeout: 3 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Validate Basic Auth
        auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

        if len(auth) != 2 || auth[0] != "Basic" {
            http.Error(w, "authorization failed", http.StatusUnauthorized)
            return
		}
		
		// Basic Auth for initial token
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !validate(pluginConf, pair[0], pair[1]) {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		// Auth ready now create session
		rq, err := http.NewRequest(http.MethodPost, pluginConf.Posturl, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rs, err := client.Do(rq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotAcceptable)
			return
		}
		defer rs.Body.Close()

		for _, cookie := range rs.Cookies() {
			//fmt.Println("Found a cookie named:", cookie.Name, cookie.Value)
			if cookie.Name == "SAKAIID" {
				r.AddCookie(cookie)
				jwtToken := base64.StdEncoding.EncodeToString([]byte(cookie.Raw))
				w.Header().Set("X-JWT-TOKEN",jwtToken)
			}
		}

		//fmt.Fprintf(w, "{\"message\": \"Hello, %s\"}", "PEPE")

	}), nil
}
