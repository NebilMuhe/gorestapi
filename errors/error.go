package errors

import "github.com/joomcode/errorx"

var (
	unableToCreate    = errorx.NewNamespace("unable to create")
	ErrUnableToCreate = errorx.NewType(unableToCreate, "unable to create")
)
