package types

import (
	"github.com/go-kit/kit/endpoint"
)

// AccountResponse defines an account response
type AccountResponse struct {
	FirstName     string
	LastName      string
	PhoneNumber   string
	Company       string
	Username      string
	AccountNumber string
	Password      string
	ResetToken    string
	Team          string
	IsAdmin       bool
}

// LoginRequest defines an account response
type LoginRequest struct {
	Auth Auth
}

// ResetPasswordRequest wraps a request to reset a password
type ResetPasswordRequest struct {
	Username string `json:"target"`
}

// ResetPasswordRequestResponse wraps a response to reset a password, passing just the HTTP response code
type ResetPasswordRequestResponse struct {
	HTTPStatusCode int
}

// CreateUserRequest wraps a request to create a new user
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
	ResetToken    string `json:"resettoken,omitempty"`
	Team          string `json:"team,omitempty"`
	IsAdmin       bool   `json:"isadmin"`
}

// Auth represent an authentication request
type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Endpoints wraps all endpoints in a struct
type Endpoints struct {
	LoginEndpoint                endpoint.Endpoint
	CreateUserEndpoint           endpoint.Endpoint
	ResetPasswordRequestEndpoint endpoint.Endpoint
}
