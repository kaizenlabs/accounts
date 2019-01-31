package types

import (
	"time"

	"github.com/go-kit/kit/endpoint"
)

// AccountResponse defines an account response
type AccountResponse struct {
	FirstName     string `json:"FirstName"`
	LastName      string `json:"LastName"`
	PhoneNumber   string `json:"PhoneNumber"`
	Company       string `json:"Company"`
	Username      string `json:"Username"`
	AccountNumber string `json:"AccountNumber"`
	Team          string `json:"Team"`
	IsAdmin       bool   `json:"IsAdmin"`
	TokenString   string
}

// LoginRequest defines an account response
type LoginRequest struct {
	Auth Auth
}

// ResetPassword wraps a request to reset a password request
type ResetPassword struct {
	Username string `json:"target"`
	Password string `json:"objective"`
	Token    string `json:"token"`
}

// ResetPasswordResponse wraps a response to reset a password, passing just the HTTP response code
type ResetPasswordResponse struct {
	HTTPStatusCode int
}

// CreateUserRequest wraps a request to create a new user
type CreateUserRequest struct {
	Account Account
}

// Account defines a user account
type Account struct {
	FirstName     string    `json:"firstName"`
	LastName      string    `json:"lastName"`
	PhoneNumber   string    `json:"phoneNumber"`
	Company       string    `json:"company"`
	Username      string    `json:"username"`
	Password      string    `json:"password,omitempty"`
	AccountNumber string    `json:"accountNumber"`
	ResetToken    string    `json:"resettoken,omitempty"`
	Team          string    `json:"team"`
	IsAdmin       bool      `json:"isadmin"`
	Fingerprints  []string  `json:"fingerprints,omitempty"`
	LastLogin     time.Time `json:"lastlogin,omitempty"`
	License       string    `json:"license,omitempty"`
	Locked        time.Time `json:"locked,omitempty"`
	LoginAttempts int       `json:"loginattempts,omitempty"`
}

// Auth represent an authentication request
type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Endpoints wraps all endpoints in a struct
type Endpoints struct {
	LoginEndpoint         endpoint.Endpoint
	CreateUserEndpoint    endpoint.Endpoint
	ResetPasswordEndpoint endpoint.Endpoint
}
