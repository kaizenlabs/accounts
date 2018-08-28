package service

import (
	"net/http"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

// RequestFunc is a middleware function for outgoing HTTP requests
type RequestFunc func(req *http.Request) *http.Request

// ToHTTPRequest returns a RequestFunc that injects an OpenTracing Span found in
// context into the HTTP Headers. If no such Span can be found, the RequestFunc
// is a noop.
func ToHTTPRequest(tracer opentracing.Tracer) RequestFunc {
	return func(req *http.Request) *http.Request {
		// Get span from context
		if span := opentracing.SpanFromContext(req.Context()); span != nil {

			ext.SpanKindRPCClient.Set(span)

			ext.HTTPMethod.Set(span, req.Method)
		}
	}
}
