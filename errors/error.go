package errors

import (
	"net/http"

	"github.com/joomcode/errorx"
)

type ErrorResponse struct {
	ErrorType *errorx.Type
	Status    int
	Error     string
}

var Errorsvalue = []ErrorResponse{
	{
		ErrorType: ErrUnableToCreate,
		Status:    http.StatusInternalServerError,
		Error:     "UNABLE_TO_CREATE",
	},
	{
		ErrorType: ErrBadRequest,
		Status:    http.StatusBadRequest,
		Error:     "UNABLE_TO_READ",
	},
	{
		ErrorType: ErrRequestTimeout,
		Status:    http.StatusRequestTimeout,
		Error:     "REQUEST_TIMEOUT",
	},
}

var (
	unableToCreate    = errorx.NewNamespace("unable to create")
	ErrUnableToCreate = errorx.NewType(unableToCreate, "unable to create")
	badRequest        = errorx.NewNamespace("invalid input")
	ErrBadRequest     = errorx.NewType(badRequest, "invalid input")
	requestTimeout    = errorx.NewNamespace("request timeout")
	ErrRequestTimeout = errorx.NewType(requestTimeout, "request timeout")
)
