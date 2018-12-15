package service

import (
	"context"
	"strconv"
	"time"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/go-kit/kit/metrics"
	"github.com/johnantonusmaximus/accounts/service/types"
	opentracing "github.com/opentracing/opentracing-go"
	opentracinglog "github.com/opentracing/opentracing-go/log"
	"github.com/spf13/viper"
)

// InstrumentingMiddleware sets up all instrumentation middleware for the service
func InstrumentingMiddleware(requestCount metrics.Counter, requestLatency metrics.Histogram, accountServiceCircuit metrics.Gauge) Middleware {
	return func(next Service) Service {
		return &instrumentingMiddleware{
			requestCount,
			requestLatency,
			accountServiceCircuit,
			next,
		}
	}
}

func (m *instrumentingMiddleware) LoginUserService(ctx context.Context, req types.LoginRequest) (r types.AccountResponse, err error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "LoginUser")
	defer span.Finish()
	span.LogFields(
		opentracinglog.String("Username", req.Auth.Username),
		opentracinglog.String("method", "LoginUser"),
	)

	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		m.requestCount.With("method", "LoginUser", "code", code, "granularity", "total").Add(1)
		m.requestLatency.With("method", "LoginUser", "granularity", "total").Observe(time.Since(begin).Seconds())
		m.circuitStatus.With("circuit_name", "LoginUser").Set(getCircuitStatus("LoginUser"))
	}(time.Now())
	if err != nil {
		span.SetTag("error", err.Error())
	}

	r, err = m.next.LoginUserService(ctx, req)
	return r, err
}

func (m *instrumentingMiddleware) CreateUserService(ctx context.Context, req types.CreateUserRequest) (r types.AccountResponse, err error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "CreateUser")
	defer span.Finish()
	span.LogFields(
		opentracinglog.String("Username", req.Account.Username),
		opentracinglog.String("method", "CreateUser"),
	)

	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		m.requestCount.With("method", "CreateUser", "code", code, "granularity", "total").Add(1)
		m.requestLatency.With("method", "CreateUser", "granularity", "total").Observe(time.Since(begin).Seconds())
		m.circuitStatus.With("circuit_name", "CreateUser").Set(getCircuitStatus("CreateUser"))
	}(time.Now())
	if err != nil {
		span.SetTag("error", err.Error())
	}
	r, err = m.next.CreateUserService(ctx, req)
	return r, err
}

func (m *instrumentingMiddleware) GetConfig() *viper.Viper {
	return m.next.GetConfig()
}

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	circuitStatus  metrics.Gauge
	next           Service
}

func getCircuitStatus(circuitName string) float64 {
	circuit, _, _ := hystrix.GetCircuit(circuitName)
	var open float64
	switch circuit.IsOpen() {
	case true:
		open = 1
	default:
		open = 0
	}
	return open
}
