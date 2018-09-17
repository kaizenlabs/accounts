package types

import (
	"github.com/go-kit/kit/endpoint"
)

type AccountResponse struct {
	FirstName     string
	LastName      string
	PhoneNumber   string
	Company       string
	Username      string
	AccountNumber string
}

type LoginRequest struct {
	Auth Auth
}

type CreateUserRequest struct {
	Auth    Auth
	Account Account
}

// Account defines a user account
type Account struct {
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	PhoneNumber   string `json:"phoneNumber"`
	Company       string `json:"company"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	AccountNumber string `json:"accountNumber"`
}

// Auth represent an authentication request
type Auth struct {
	Username string
	Password string
}

// Endpoints wraps all endpoints in a struct
type Endpoints struct {
	LoginEndpoint      endpoint.Endpoint
	CreateUserEndpoint endpoint.Endpoint
}
