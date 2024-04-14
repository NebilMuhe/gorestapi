package errors

import "github.com/joomcode/errorx"

var (
	unableToLoad    = errorx.NewNamespace("unable to load")
	ErrUnableToLoad = errorx.NewType(unableToLoad, "unable to load")
)
