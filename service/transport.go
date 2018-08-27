package service

import (
	"net/http"

	"github.com/johnantonusmaximus/go-common/src/errors"
)

// CodeFrom gets the code from the response
func CodeFrom(err error) int {
	if e, ok := err.(errors.Err); ok {
		switch e.GetCode() {
		case 400:
			return http.StatusBadRequest
		case 401:
			return http.StatusUnauthorized
		case 403:
			return http.StatusForbidden
		case 404:
			return http.StatusNotFound
		}
	}
	return http.StatusInternalServerError
}
