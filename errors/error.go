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
	{
		ErrorType: ErrInvalidInput,
		Status:    http.StatusBadRequest,
		Error:     "INVALID_CREDENTIAL",
	},
	{
		ErrorType: ErrInternalServer,
		Status:    http.StatusInternalServerError,
		Error:     "UNABLE_TO_CREATE",
	},
	{
		ErrorType: ErrUserAlreadyExists,
		Status:    http.StatusConflict,
		Error:     "UNABLE_TO_CREATE",
	},
	{
		ErrorType: ErrNotFound,
		Status:    http.StatusNotFound,
		Error:     "USER_NOT_FOUND",
	},
	{
		ErrorType: ErrUnableToRead,
		Status:    http.StatusInternalServerError,
		Error:     "UNABLE_TO_READ",
	},
	{
		ErrorType: ErrUserAlreadyLoggedIn,
		Status:    http.StatusConflict,
		Error:     "USER_ALREADY_LOGGED_IN",
	},
}

var (
	unableToCreate         = errorx.NewNamespace("unable to create")
	ErrUnableToCreate      = errorx.NewType(unableToCreate, "unable to create")
	badRequest             = errorx.NewNamespace("invalid input")
	ErrBadRequest          = errorx.NewType(badRequest, "invalid input")
	requestTimeout         = errorx.NewNamespace("request timeout")
	ErrRequestTimeout      = errorx.NewType(requestTimeout, "request timeout")
	invalidInput           = errorx.NewNamespace("invalid username email or password")
	ErrInvalidInput        = errorx.NewType(invalidInput, "invalid username email or password")
	userAlreadyExists      = errorx.NewNamespace("user already exists")
	ErrUserAlreadyExists   = errorx.NewType(userAlreadyExists, "user already exists")
	internalServer         = errorx.NewNamespace("internal server error")
	ErrInternalServer      = errorx.NewType(internalServer, "internal server error")
	notFound               = errorx.NewNamespace("not found")
	ErrNotFound            = errorx.NewType(notFound, "not found")
	unableToRead           = errorx.NewNamespace("unable to read")
	ErrUnableToRead        = errorx.NewType(unableToRead, "unable to read")
	userAlreadyLoggedIn    = errorx.NewNamespace("user already logged in")
	ErrUserAlreadyLoggedIn = errorx.NewType(userAlreadyLoggedIn, "user already logged in")
)
