package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/johnantonusmaximus/Accounts/service"
	"github.com/rs/cors"
)

// PORT is the port for the server
const PORT string = "3002"

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", service.Login).Methods("POST") // GET will be handles by React app
	r.HandleFunc("/create-user", service.CreateUser).Methods("POST")
	//originsOK := handlers.AllowedOrigins([]string{"*"})
	handler := cors.Default().Handler(r)
	fmt.Printf("Listening on port %s", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
}
