package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "app"
	clientSecret = "e36aa989-2c20-4da4-8323-e4e853514e13"
)

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://0.0.0.0:8080/auth/realms/ledivan")
	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://0.0.0.0:8081/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "exemplo"
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "State doest match", http.StatusBadRequest)
			return
		}
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Error", http.StatusInternalServerError)
			return
		}
		idToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Error", http.StatusInternalServerError)
			return
		}

		res := struct {
			Oauth2Token *oauth2.Token
			IDToken     string
		}{
			oauth2Token, idToken,
		}
		data, _ := json.MarshalIndent(res, "", " ")
		w.Write(data)
	})
	log.Fatal(http.ListenAndServe(":8081", nil))
}
