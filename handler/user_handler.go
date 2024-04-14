package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/service"
)

type server struct {
	Router *gin.Engine
}

type UserHandler interface {
	RegisterUserHandler(ctx *gin.Context)
	// LoginUserHandler(ctx *gin.Context)
}

type userHandler struct {
	service service.UserService
}

func NewServer() *server {
	return &server{
		Router: gin.Default(),
	}
}

func NewUserHandler(service service.UserService) UserHandler {
	return &userHandler{service: service}
}

// RegisterUserHandler implements UserHandler.
func (u *userHandler) RegisterUserHandler(ctx *gin.Context) {
	var user service.User

	if err := ctx.ShouldBindJSON(&user); err != nil {
		err = errors.ErrBadRequest.Wrap(err, "invalid input")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	registeredUser, err := u.service.RegisterUser(ctx, user)

	if err != nil {
		if err == context.DeadlineExceeded {
			err = errors.ErrRequestTimeout.Wrap(err, "request timeout")
			ctx.Error(err)
			ctx.Abort()
			return
		}
		ctx.Error(err)
		ctx.Abort()
		return
	}

	ctx.JSON(http.StatusCreated, registeredUser)
}
