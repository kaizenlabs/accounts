package service

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/johnantonusmaximus/Accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
)

func MakeHTTPHandler(ctx context.Context, s Service, tracer stdopentracing.Tracer, logger log.Logger) http.Handler {

}

type errorer interface {
	error() error
}

// HealthCheckHandler handles a healthcheck ping
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	io.WriteString(w, `{"alive": true}`)
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func decodeCreateUser(_ context.Context, r *http.Request) (request interface{}, err error) {
	var acc types.Account

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return types.AccountResponse{}, err
	}
	err = json.Unmarshal(body, &acc)
	if err != nil {
		return types.AccountResponse{}, err
	}
	acc.ID = 0

	return types.CreateUserRequest{
		Account: acc,
	}, nil
}

func decodeLoginUser(_ context.Context, r *http.Request) (request interface{}, err error) {
	var auth types.Auth

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return types.AccountResponse{}, err
	}
	err = json.Unmarshal(body, &auth)
	if err != nil {
		return types.AccountResponse{}, err
	}

	return types.LoginRequest{
		Auth: auth,
	}, nil
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err != nil {
		panic("encodeError with nil error")
	}
	w.Header().Set("Context-Type", "application/json; charset=utf-8")
	w.WriteHeader(CodeFrom(err))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

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
