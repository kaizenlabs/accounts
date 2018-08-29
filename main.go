package main

import (
	"context"
	"flag"
	"fmt"

	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/go-kit/kit/log"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/johnantonusmaximus/Accounts/service"
	stdopentracing "github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin/zipkin-go-opentracing"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

// PORT is the port for the server
const PORT string = "3002"

func main() {
	var tracer stdopentracing.Tracer
	{
		const zipkinHTTPEndpoint = "http://zipkin-svc.monitoring:9411/api/v1/spans"
		collector, err := zipkin.NewHTTPCollector(zipkinHTTPEndpoint)
		debug := false
		if err != nil {
			fmt.Printf("Unable to create Zipkin HTTP collector: %+v", err)
			os.Exit(-1)
		}
		hostname := os.Getenv("HOSTNAME")
		recorder := zipkin.NewRecorder(collector, debug, hostname, "Accounts")
		tracer, err = zipkin.NewTracer(
			recorder,
			zipkin.ClientServerSameSpan(true),
			zipkin.TraceID128Bit(true),
		)
		if err != nil {
			fmt.Printf("Unable to create Zipkin tracer: %+v", err)
			os.Exit(-1)
		}
	}
	stdopentracing.SetGlobalTracer(tracer)
	var (
		httpAddr = flag.String("http.addr", ":"+PORT, "HTTP listen address")
	)
	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	var ctx context.Context
	{
		ctx = context.Background()
	}

	requestCounter := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "api",
		Name:      "request",
		Help:      "Number of requests received.",
	}, []string{"method", "code", "granularity"})

	requestLatency := kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
		Namespace: "api",
		Name:      "request_latency_seconds",
		Help:      "Total duration of request in seconds.",
	}, []string{"method", "granularity"})

	circuitStatus := kitprometheus.NewGaugeFrom(stdprometheus.GaugeOpts{
		Namespace: "api",
		Name:      "circuit_status",
		Help:      "Current Hystrix circuit status.",
	}, []string{"circuit_name"})

	var s service.Service
	{
		s = service.AccountService(requestCounter, requestLatency, circuitStatus)
		s = service.LoggingMiddleware(logger)(s)
		s = service.InstrumentingMiddleware(requestCounter, requestLatency, circuitStatus)(s)
	}

	var h http.Handler
	{
		h = service.MakeHTTPHandler(ctx, s, tracer, log.With(logger, "component", "HTTP"))
	}

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		hystrix.ConfigureCommand("LoginUser", hystrix.CommandConfig{
			Timeout:               s.GetConfig().GetInt("baseTimeout"),
			MaxConcurrentRequests: 100,
			ErrorPercentThreshold: 25,
		})
		hystrix.ConfigureCommand("CreateUser", hystrix.CommandConfig{
			Timeout:               s.GetConfig().GetInt("baseTimeout"),
			MaxConcurrentRequests: 100,
			ErrorPercentThreshold: 25,
		})
		hystrixStreamHandler := hystrix.NewStreamHandler()
		hystrixStreamHandler.Start()
		go http.ListenAndServe(net.JoinHostPort("", PORT), hystrixStreamHandler)
		logger.Log("transport", "HTTP", "addr", *httpAddr)
		errs <- http.ListenAndServe(*httpAddr, h)
	}()

	logger.Log("exit", <-errs)
}
