package service

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/johnantonusmaximus/accounts/service/types"
)

// MakeServerEndpoints creates the endpoints for the server's services
func MakeServerEndpoints(s Service) types.Endpoints {
	return types.Endpoints{
		LoginEndpoint:         MakeLoginEndpoint(s),
		CreateUserEndpoint:    MakeCreateUserEndpoint(s),
		ResetPasswordEndpoint: MakeResetPasswordEndpoint(s),
	}
}

// MakeLoginEndpoint creates the endpoints for the server's services
func MakeLoginEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(types.LoginRequest)
		r, e := s.LoginUserService(ctx, req)
		return &getAccountResponse{r}, e
	}
}

// MakeCreateUserEndpoint creates the endpoints for creating new users
func MakeCreateUserEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(types.CreateUserRequest)
		r, e := s.CreateUserService(ctx, req)
		return &getAccountResponse{r}, e
	}
}

// MakeResetPasswordEndpoint creates the endpoints for resetting a users password
func MakeResetPasswordEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(types.ResetPassword)
		r, e := s.ResetPasswordService(ctx, req)
		return &getResetPasswordResponse{r}, e
	}
}

// response for request
// swagger:response productResponse
type getAccountResponse struct {
	types.Account
}

type getResetPasswordResponse struct {
	types.ResetPasswordResponse
}
