package handler

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, cancel := context.WithTimeout(ctx.Request.Context(), timeout)
		defer cancel()
	}
}
