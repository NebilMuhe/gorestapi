package handler

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joomcode/errorx"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/service"
)

func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		c, cancel := context.WithTimeout(ctx.Request.Context(), timeout)
		defer cancel()
		requestID, err := service.GenerateRequestID(ctx)
		if err != nil {
			ctx.Abort()
			return
		}

		ctx.Set("requestID", requestID)
		ctx.Request = ctx.Request.WithContext(c)
		ctx.Next()

		if ctx.Errors != nil {
			errorHandlerMiddleware(ctx)
		}
	}
}

func errorHandlerMiddleware(ctx *gin.Context) {
	err := ctx.Errors.Last()
	if err != nil {
		e := err.Unwrap()
		for _, er := range errors.Errorsvalue {

			if errorx.IsOfType(e, er.ErrorType) {
				errr := errorx.Cast(e)
				ctx.JSON(er.Status, gin.H{
					"Status":       er.Status,
					"ErrorMessage": errr.Message(),
					"Error":        e.Error(),
				})
			}
			// fmt.Println("false")
		}
	}
}
