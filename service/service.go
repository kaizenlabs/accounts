package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/asdine/storm"
	"github.com/go-kit/kit/metrics"
	opentracing "github.com/opentracing/opentracing-go"

	"github.com/johnantonusmaximus/Accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// AccountService wraps the login service with latency and circuit metrics
type accountService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	circuitStatus  metrics.Gauge
	config         viper.Viper
}

// AccountService instantiates the Account service with counters, latency, metrics, and circuit status
func AccountService(requestCount metrics.Counter, requestLatency metrics.Histogram, circuitStatus metrics.Gauge) Service {
	config := InitConfig("./conf")
	return &accountService{requestCount, requestLatency, circuitStatus, *config}
}

// Service defines an Accounts service interface for Go-Kit
type Service interface {
	LoginUser(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error)
	CreateUser(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error)
	GetConfig() *viper.Viper
}

func (a accountService) GetConfig() *viper.Viper {
	return &a.config
}

// LoginUser logs in a user
func (a accountService) LoginUser(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return types.AccountResponse{}, errors.ErrMissingParametersReason.New("Username or password is missing")
	}

	LoginResponse, err := a.Login(ctx, req)

	return LoginResponse, err
}

// CreateUser creates a new user
func (a accountService) CreateUser(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	if req.Account.AccountNumber == "" || req.Account.Company == "" || req.Account.FirstName == "" || req.Account.LastName == "" || req.Account.PhoneNumber == "" || req.Account.Username == "" {
		return types.AccountResponse{}, errors.ErrMissingParametersReason.New("Missing parameters for account creation")
	}

	CreateUserResponse, err := a.CreateUser(ctx, req)

	return CreateUserResponse, err
}

// Login logs in a user
func (a accountService) Login(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	output := make(chan bool, 1)
	var err error
	var loginResponse types.AccountResponse
	errs := hystrix.Go("LoginUser", func() error {
		loginResponse, err = a.GetUserDataFromDB(ctx, req)
		fmt.Printf("Err: %s", err)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		output <- true
		return nil
	}, nil)

	select {
	case out := <-output:
		if out {
			return loginResponse, err
		}
	case err := <-errs:
		return loginResponse, err
	}

	return loginResponse, err

}

// GetUserDataFromDB gets the user from the database
func (a accountService) GetUserDataFromDB(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
	var acc types.Account
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "LoginUser", "code", code, "granularity", "login_user").Add(1)
		a.requestLatency.With("method", "LoginUser", "granularity", "login_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "LoginUser").Set(getCircuitStatus("LoginUser"))
	}(time.Now())

	db, err := storm.Open("account.db")
	if err != nil {
		return resp, err
	}
	defer db.Close()
	err = db.One("Username", req.Auth.Username, &acc)
	if err != nil {
		return resp, err
	}

	err = comparePassword(acc.Password, req.Auth.Password)
	if err != nil {
		return resp, err
	}
	resp = types.AccountResponse{
		FirstName:     acc.FirstName,
		LastName:      acc.LastName,
		PhoneNumber:   acc.PhoneNumber,
		Company:       acc.Company,
		Username:      acc.Username,
		AccountNumber: acc.AccountNumber,
	}

	return resp, err
}

// CreateUser creates a new user
func CreateUser(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	var resp types.AccountResponse
	var err error
	db, err := storm.Open("account.db")
	if err != nil {
		return resp, err
	}
	defer db.Close()

	errString := checkForDataErrors(req.Account)
	if len(errString) > 0 {
		fmt.Println("Error returned!")
		return resp, err
	}

	hashedPassword, err := hashAndSaltPassword([]byte(req.Account.Password))
	if err != nil {
		return resp, err
	}
	req.Account.Password = hashedPassword
	req.Account.ID = 0

	err = db.Save(&req)
	if err != nil {
		return resp, err
	}
	resp = types.AccountResponse{
		FirstName:     req.Account.FirstName,
		LastName:      req.Account.LastName,
		PhoneNumber:   req.Account.PhoneNumber,
		Company:       req.Account.Company,
		Username:      req.Account.Username,
		AccountNumber: req.Account.AccountNumber,
	}
	return resp, err
}

func hashAndSaltPassword(p []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(p, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePassword(hashedPassword string, plainPwd string) error {
	hashBytes := []byte(hashedPassword)
	hashAttempt := []byte(plainPwd)

	err := bcrypt.CompareHashAndPassword(hashBytes, hashAttempt)
	if err != nil {
		return err
	}

	return nil
}

func checkForDataErrors(acc types.Account) string {
	if len(acc.Password) < 5 {
		return "Password not long enough"
	}

	if len(acc.Username) < 1 {
		return "No username provided"
	}

	if len(acc.FirstName) < 1 {
		return "No first name provided"
	}

	if len(acc.LastName) < 1 {
		return "No last name provided"
	}

	if len(acc.PhoneNumber) < 1 {
		return "No phone number provided"
	}

	if len(acc.AccountNumber) < 1 {
		return "No account number provided"
	}

	return ""
}

func errorResponse(w http.ResponseWriter, code int, err error, response []byte) {
	log.Println("SERVER ERROR:", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if len(response) > 0 {
		w.Write(response)
	}
}

func successResponse(w http.ResponseWriter, code int, response []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
