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
}

var (
	unableToCreate    = errorx.NewNamespace("unable to create")
	ErrUnableToCreate = errorx.NewType(unableToCreate, "unable to create")
)
