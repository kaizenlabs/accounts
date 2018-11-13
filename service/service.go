package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	datastore "cloud.google.com/go/datastore"
	"github.com/afex/hystrix-go/hystrix"
	logga "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/johnantonusmaximus/Ethos-App/Accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// AccountService wraps the login service with latency and circuit metrics
type accountService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	circuitStatus  metrics.Gauge
	config         viper.Viper
	client         *datastore.Client
}

// AccountService instantiates the Account service with counters, latency, metrics, and circuit status
func AccountService(requestCount metrics.Counter, requestLatency metrics.Histogram, circuitStatus metrics.Gauge) Service {
	config := InitConfig("./conf")
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}
	return &accountService{requestCount, requestLatency, circuitStatus, *config, client}
}

// Service defines an Accounts service interface for Go-Kit
type Service interface {
	LoginUserService(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error)
	CreateUserService(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error)
	GetConfig() *viper.Viper
}

func (a accountService) GetConfig() *viper.Viper {
	return &a.config
}

// LoginUser logs in a user
func (a accountService) LoginUserService(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return types.AccountResponse{}, errors.ErrMissingParametersReason.New("Username or password is missing")
	}
	LoginResponse, err := a.Login(ctx, req)

	return LoginResponse, err
}

// CreateUser creates a new user
func (a accountService) CreateUserService(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
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
		var logger logga.Logger
		logger.Log("Getting user from DB...")
		loginResponse, err = a.GetUserDataFromDB(ctx, req)
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

// Login logs in a user
func (a accountService) CreateUser(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	output := make(chan bool, 1)
	var err error
	var createUserResponse types.AccountResponse
	errs := hystrix.Go("CreateUser", func() error {
		err = a.CheckForUserInDB(ctx, req)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		createUserResponse, err = a.CreateUserInDB(ctx, req)
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
			return createUserResponse, err
		}
	case err := <-errs:
		return createUserResponse, err
	}

	return createUserResponse, err

}

// GetUserDataFromDB gets the user from the database
func (a accountService) GetUserDataFromDB(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
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

	var logger logga.Logger
	{
		logger = logga.NewLogfmtLogger(os.Stderr)
		logger = logga.With(logger, "ts", logga.DefaultTimestampUTC)
		logger = logga.With(logger, "caller", logga.DefaultCaller)
	}
	logger.Log("AuthRequest:", req.Auth)
	key := datastore.NameKey("Account", req.Auth.Username, nil)
	acc := new(types.Account)
	if err = a.client.Get(ctx, key, acc); err != nil {
		return resp, err
	}
	logger.Log("Datastore entity retrieved!")

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

// GetUserDataFromDB gets the user from the database
func (a accountService) CheckForUserInDB(ctx context.Context, req types.CreateUserRequest) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "check_for_user")
	defer span.Finish()
	var err error
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "LoginUser", "code", code, "granularity", "check_for_user").Add(1)
		a.requestLatency.With("method", "LoginUser", "granularity", "check_for_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "CreateUser").Set(getCircuitStatus("createUser"))
	}(time.Now())

	// Datastore query here
	key := datastore.NameKey("Account", req.Account.Username, nil)
	acc := new(types.Account)
	log.Println("AccountToCheckFor:", req.Account)
	if err = a.client.Get(ctx, key, acc); err == nil {
		return errors.ErrDuplicate
	}
	return nil
}

// CreateUser creates a new user
func (a accountService) CreateUserInDB(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "CreateUser", "code", code, "granularity", "create_user").Add(1)
		a.requestLatency.With("method", "CreateUser", "granularity", "create_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "CreateUser").Set(getCircuitStatus("CreateUser"))
	}(time.Now())

	errString := checkForDataErrors(req.Account)
	if len(errString) > 0 {
		return resp, err
	}

	hashedPassword, err := hashAndSaltPassword([]byte(req.Account.Password))
	if err != nil {
		return resp, err
	}
	req.Account.Password = hashedPassword
	accPtr := &req.Account

	newKey := datastore.NameKey("Account", req.Account.Username, nil)
	log.Println("CreateAccountRequest:", req.Account)
	fmt.Println("CreateAccountRequest:", req.Account)
	_, err = a.client.Put(ctx, newKey, accPtr)
	if err != nil {
		return resp, err
	}
	fmt.Println("Datastore query finished!")

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
