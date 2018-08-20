package types

type LoginResponse struct {
	FirstName     string
	LastName      string
	PhoneNumber   string
	Company       string
	Username      string
	AccountNumber string
}

type LoginEndpointRequest struct {
}

// Account defines a user account
type Account struct {
	ID            int    `storm:"id,increment=100"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	PhoneNumber   string `json:"phoneNumber"`
	Company       string `json:"company" storm:"index"`
	Username      string `json:"username" storm:"unique"`
	Password      string `json:"password"`
	AccountNumber string `json:"accountNumber" storm:"index"`
}

// Auth represent an authentication request
type Auth struct {
	Username string
	Password string
}
