package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
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
			fmt.Println("error")
		}
	}
}
