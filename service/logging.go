package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/johnantonusmaximus/accounts/service/types"
	"github.com/spf13/viper"
)

// Middleware is a function that return a Service
type Middleware func(Service) Service

// LoggingMiddleware is middlware configuration for logging
func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (m loggingMiddleware) CreateUserService(ctx context.Context, req types.CreateUserRequest) (r types.AccountResponse, err error) {
	if shouldLog(err, m) {
		defer func(begin time.Time) {
			m.logger.Log("method", "CreateUser", "Username", req.Account.Username, "FirstName", req.Account.FirstName, "LastName", req.Account.LastName, "PhoneNumber", req.Account.PhoneNumber, "Company", req.Account.Company, "AccountNumber", req.Account.AccountNumber, "took", fmt.Sprintf("%vms", time.Since(begin).Seconds()*1000), "err", err)
		}(time.Now())
	}
	return m.next.CreateUserService(ctx, req)
}

func (m loggingMiddleware) LoginUserService(ctx context.Context, req types.LoginRequest) (r types.AccountResponse, err error) {
	if shouldLog(err, m) {
		defer func(begin time.Time) {
			m.logger.Log("method", "LoginUser", "Username", req.Auth.Username, "Password", req.Auth.Password, "took", fmt.Sprintf("%vms", time.Since(begin).Seconds()*1000), "err", err)
		}(time.Now())
	}
	return m.next.LoginUserService(ctx, req)
}

func (m loggingMiddleware) ResetPasswordService(ctx context.Context, req types.ResetPassword) (r types.ResetPasswordResponse, err error) {
	if shouldLog(err, m) {
		defer func(begin time.Time) {
			m.logger.Log("method", "ResetPassword", "Username", req.Username, "took", fmt.Sprintf("%vms", time.Since(begin).Seconds()*1000), "err", err)
		}(time.Now())
	}
	return m.next.ResetPasswordService(ctx, req)
}

func (m loggingMiddleware) GetConfig() *viper.Viper {
	return m.next.GetConfig()
}

func shouldLog(err error, m loggingMiddleware) bool {
	if err != nil || m.next.GetConfig().GetBool("debug") {
		return true
	}
	return false
}
