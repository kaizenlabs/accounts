package service

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/openzipkin/zipkin-go-opentracing/thrift/gen-go/zipkincore"
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
			span.SetTag(zipkincore.HTTP_HOST, req.URL.Host)
			span.SetTag(zipkincore.HTTP_PATH, req.URL.Path)
			ext.HTTPUrl.Set(
				span,
				fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path),
			)

			// Add information on the peer service we're contacting
			if host, portString, err := net.SplitHostPort(req.URL.Host); err == nil {
				ext.PeerHostname.Set(span, host)
				if port, err := strconv.Atoi(portString); err != nil {
					ext.PeerPort.Set(span, uint16(port))
				}
			} else {
				ext.PeerHostname.Set(span, req.URL.Host)
			}

			if err := tracer.Inject(
				span.Context(),
				opentracing.TextMap,
				opentracing.HTTPHeadersCarrier(req.Header),
			); err != nil {
				fmt.Printf("error encountered while trying to inject span: %+v", err)
			}
		}
		return req
	}
}

// HandlerFunc is a func that returns a handler
type HandlerFunc func(next http.Handler) http.Handler

// FromHTTPRequest returns a HandlerFunc that tries to join with an
// OpenTracing trace found in the HTTP request headers and starts a new span
// called "operationName". If no trace can be found in the headers,
// the span will be a trace root. The span is incorporated in the HTTP Context Object
// and can be retrieved with the opentracing.SpanFromContext(ctx) method.
func FromHTTPRequest(tracer opentracing.Tracer, operationName string) HandlerFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			wireContext, err := tracer.Extract(
				opentracing.TextMap,
				opentracing.HTTPHeadersCarrier(req.Header),
			)
			if err != nil {
				fmt.Printf("error encountered whilte trying to extract span: %+v\n", err)
			}

			// create span
			span := tracer.StartSpan(operationName, ext.RPCServerOption(wireContext))
			span.SetTag("serverSide", "here")
			defer span.Finish()

			// store span in context
			ctx := opentracing.ContextWithSpan(req.Context(), span)

			// include new span in request
			req = req.WithContext(ctx)

			// next middleware or actual request handler
			next.ServeHTTP(w, req)
		})
	}
}
