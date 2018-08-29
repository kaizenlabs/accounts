package service

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	httpprof "net/http/pprof"
	"os"

	"github.com/go-kit/kit/log"
	opentracing "github.com/go-kit/kit/tracing/opentracing"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/johnantonusmaximus/Accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHTTPHandler creates the handler for decoding and encoding HTTP responses as well as handling routing via Gorilla Mux Router
// Mounts all service endpoitns into a single http.Handler
func MakeHTTPHandler(ctx context.Context, s Service, tracer stdopentracing.Tracer, logger log.Logger) http.Handler {
	r := mux.NewRouter()
	contextPath := os.Getenv("CONTEXT_PATH")
	sub := r
	if contextPath != "" {
		sub = r.PathPrefix(contextPath).Subrouter()
	}
	if s.GetConfig().GetBool("swagger") {
		path := "/asset"
		if s.GetConfig().GetString("ENV") == "" {
			path = "." + path
		}

		prefix := contextPath + "swagger-ui/"
		if contextPath == "" {
			prefix = "/swagger-ui/"
		}
		sub.PathPrefix("/swagger-ui/").Handler(http.StripPrefix(prefix, http.FileServer(http.Dir(path))))

	}
	e := MakeServerEndpoints(s)

	options := []httptransport.ServerOption{
		httptransport.ServerErrorLogger(logger),
		httptransport.ServerErrorEncoder(encodeError),
	}

	sub.Methods("POST").Path("/v1/login").Handler(httptransport.NewServer(
		e.LoginEndpoint,
		decodeLoginUser,
		encodeResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(tracer, "LoginUser", logger)))...,
	))

	sub.Methods("POST").Path("/v1/create-user").Handler(httptransport.NewServer(
		e.CreateUserEndpoint,
		decodeCreateUser,
		encodeResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(tracer, "CreateUser", logger)))...,
	))

	sub.HandleFunc("/debug/pprof/", httpprof.Index)
	sub.HandleFunc("/debug/pprof/cmdline", httpprof.Cmdline)
	sub.HandleFunc("/debug/pprof/profile", httpprof.Profile)
	sub.HandleFunc("/debug/pprof/symbol", httpprof.Symbol)
	sub.HandleFunc("/debug/pprof/trace", httpprof.Trace)
	sub.Handle("/debug/pprof/goroutine", httpprof.Handler("goroutine"))
	sub.Handle("/debug/pprof/heap", httpprof.Handler("heap"))
	sub.Handle("/debug/pprof/threadcreate", httpprof.Handler("threadcreate"))
	sub.Handle("/debug/pprof/block", httpprof.Handler("block"))
	sub.Handle("/metrics", promhttp.HandlerFor(stdprometheus.DefaultGatherer, promhttp.HandlerOpts{}))
	sub.HandleFunc("/health", HealthCheckHandler)
	//originsOK := handlers.AllowedOrigins([]string{"*"})
	return sub
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
	if err == nil {
		panic("encodeError with nil error")
	}
	if CodeFrom(err) == 500 && err.Error() == "crypto/bcrypt: hashedPassword is not the hash of the given password" {
		w.Header().Set("Context-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Unauthorized",
		})
	} else if CodeFrom(err) == 500 && err.Error() == "not found" {
		w.Header().Set("Context-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Unauthorized",
		})
	} else if CodeFrom(err) == 400 && err.Error() == "Missing parameters: Username or password is missing" {
		w.Header().Set("Context-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		w.Header().Set("Context-Type", "application/json; charset=utf-8")
		w.WriteHeader(CodeFrom(err))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Bad Request",
		})
	}
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
