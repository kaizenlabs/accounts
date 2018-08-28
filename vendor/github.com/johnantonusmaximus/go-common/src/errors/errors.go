package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Err struct {
	code int
	msg  string
}

var (
	ErrPartialContent       = Err{206, "Partial content"}
	ErrPartialContentReason = Err{206, "Partial content: %s"}

	ErrNotModified       = Err{304, "Not modified"}
	ErrNotModifiedReason = Err{304, "Not modified: %s"}

	ErrBadRequest       = Err{400, "Bad request"}
	ErrBadRequestReason = Err{400, "Bad request: %s"}

	ErrInvalidJson       = Err{400, "Invalid json"}
	ErrInvalidJsonReason = Err{400, "Invalid json: %s"}

	ErrMissingParameters       = Err{400, "Missing parameters"}
	ErrMissingParametersReason = Err{400, "Missing parameters: %s"}

	ErrUnauthorized       = Err{401, "Unauthorized"}
	ErrUnauthorizedReason = Err{401, "Unauthorized: %s"}

	ErrForbidden       = Err{403, "Forbidden"}
	ErrForbiddenReason = Err{403, "Forbidden: %s"}

	ErrNotFound       = Err{404, "Not found"}
	ErrNotFoundReason = Err{404, "Not found: %s"}

	ErrItemExists       = Err{409, "Item Exists"}
	ErrItemExistsReason = Err{409, "Item exists: %s"}

	ErrServerError       = Err{500, "Endpoint error"}
	ErrServerErrorReason = Err{500, "Endpoint error: %s"}

	ErrDuplicate       = Err{422, "Duplicate value"}
	ErrDuplicateReason = Err{422, "Duplicate value: %s"}

	ErrBadGateway       = Err{502, "Gateway error"}
	ErrBadGatewayReason = Err{502, "Gateway error: %s"}

	ErrCustom = Err{0, "%s"}
)

func (e Err) Error() string {
	return e.msg
}

func (e Err) New(params ...interface{}) Err {
	e.msg = fmt.Sprintf(e.msg, params...)
	return e
}

func (e Err) SetCode(code int) Err {
	e.code = code
	return e
}

func (e Err) GetCode() int {
	return e.code
}

func CodeFrom(err error) int {
	if e, ok := err.(Err); ok {
		return e.GetCode()
	}

	return http.StatusInternalServerError
}

type EndpointError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
}

type EndpointErrors struct {
	Errors []EndpointError `json:"errors,omitempty"`
	EndpointError
}

func (e EndpointErrors) String() string {
	var s []string
	for _, err := range e.Errors {
		s = append(s, err.Message)
	}
	return strings.Join(s, "\n")
}

func GetErrorsFromResponse(statusCode int, body []byte) error {
	var errs EndpointErrors
	_ = json.Unmarshal(body, &errs)
	if len(errs.Errors) > 0 {
		switch statusCode {
		case 400:
			// TODO Remove this capturing of 400 so we can get the alerts as endpoint errors
			return ErrBadRequestReason.New(errs.String())
		case 401:
			return ErrUnauthorized.New(errs.String())
		case 404:
			return ErrNotFoundReason.New(errs.String())
		case 503:
			return ErrServerErrorReason.New("Service unavailable")
		default:
			return ErrServerErrorReason.New(errs.String())
		}
	}

	var err EndpointError
	_ = json.Unmarshal(body, &err)
	switch statusCode {
	case 400:
		// TODO Remove this capturing of 400 so we can get the alerts as endpoint errors
		return ErrBadRequestReason.New(err.Message)
	case 401:
		return ErrUnauthorized.New(err.Message)
	case 404:
		return ErrNotFoundReason.New(err.Message)
	case 503:
		return ErrServerErrorReason.New("Service unavailable")
	default:
		return ErrServerErrorReason.New(err.Message)
	}
}
