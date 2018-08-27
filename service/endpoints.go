package service

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/johnantonusmaximus/Accounts/service/types"
)

func MakeServerEndpoints(s Service) types.Endpoints {
	return types.Endpoints{
		LoginEndpoint: MakeLoginEndpoint(s),
		CreateUser:    MakeCreateUserEndpoint(s),
	}
}

func MakeLoginEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		r, e := s.LoginService(ctx, req)
		return LoginResponse{r}, e
	}
}
