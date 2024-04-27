package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joomcode/errorx"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/helpers"
)

func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		fmt.Println("it does not work")
		c, cancel := context.WithTimeout(ctx.Request.Context(), timeout)
		defer cancel()
		requestID := helpers.GenerateRequestID(ctx)
		fmt.Println("request id", requestID)

		fmt.Println("why the middleware does not work")
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
		isFound := false
		e := err.Unwrap()
		for _, er := range errors.Errorsvalue {
			if errorx.IsOfType(e, er.ErrorType) {
				isFound = true
				errr := errorx.Cast(e)
				if errr == nil {
					ctx.JSON(http.StatusInternalServerError, gin.H{
						"ErrorMessage": "unknown error",
					})
					return
				}

				ctx.JSON(er.Status, gin.H{
					"Status":       er.Status,
					"ErrorMessage": errr.Message(),
					"Error":        e.Error(),
				})
				return
			}
		}

		if !isFound {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"ErrorMessage": "unknown error",
			})
			return
		}
	}
}
