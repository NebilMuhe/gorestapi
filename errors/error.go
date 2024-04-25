package errors

import (
	"net/http"

	"github.com/joomcode/errorx"
)

type ErrorResponse struct {
	ErrorType *errorx.Type
	Status    int
}

var Errorsvalue = []ErrorResponse{
	{
		ErrorType: ErrUnableToCreate,
		Status:    http.StatusInternalServerError,
	},
	{
		ErrorType: ErrBadRequest,
		Status:    http.StatusBadRequest,
	},
	{
		ErrorType: ErrRequestTimeout,
		Status:    http.StatusRequestTimeout,
	},
	{
		ErrorType: ErrInvalidInput,
		Status:    http.StatusBadRequest,
	},
	{
		ErrorType: ErrInternalServer,
		Status:    http.StatusInternalServerError,
	},
	{
		ErrorType: ErrUserAlreadyExists,
		Status:    http.StatusConflict,
	},
	{
		ErrorType: ErrNotFound,
		Status:    http.StatusNotFound,
	},
	{
		ErrorType: ErrUnableToRead,
		Status:    http.StatusInternalServerError,
	},
	{
		ErrorType: ErrUserAlreadyLoggedIn,
		Status:    http.StatusPermanentRedirect,
	},
	{
		ErrorType: ErrUnableToFind,
		Status:    http.StatusBadRequest,
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
	ErrNotFound            = errorx.NewType(notFound, "invalid credential")
	unableToRead           = errorx.NewNamespace("unable to read")
	ErrUnableToRead        = errorx.NewType(unableToRead, "unable to read")
	userAlreadyLoggedIn    = errorx.NewNamespace("user already logged in")
	ErrUserAlreadyLoggedIn = errorx.NewType(userAlreadyLoggedIn, "user already logged in")
	unableToFind           = errorx.NewNamespace("unable to find")
	ErrUnableToFind        = errorx.NewType(unableToFind, "unable to find")
)
