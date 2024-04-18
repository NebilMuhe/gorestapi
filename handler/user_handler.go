package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/service"
)

type server struct {
	Router *gin.Engine
}

type UserHandler interface {
	RegisterUserHandler(ctx *gin.Context)
	LoginUserHandler(ctx *gin.Context)
	RefreshTokenHandler(ctx *gin.Context)
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
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")

	if err := ctx.ShouldBindJSON(&user); err != nil {
		err = errors.ErrBadRequest.Wrap(err, "invalid input")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	registeredUser, err := u.service.RegisterUser(reqCtx, requestID.(string), user)

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

// LoginUserHandler implements UserHandler.
func (u *userHandler) LoginUserHandler(ctx *gin.Context) {
	var user service.UserLogin
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")

	if err := ctx.ShouldBindJSON(&user); err != nil {
		err = errors.ErrBadRequest.Wrap(err, "invalid input")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	token, err := u.service.LoginUser(reqCtx, requestID.(string), user)

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

	ctx.JSON(http.StatusOK, token)
}

func (u *userHandler) RefreshTokenHandler(ctx *gin.Context) {
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")

	authorization := ctx.Request.Header.Get("Authorization")
	if authorization == "" || !strings.HasPrefix(authorization, "Bearer ") {
		err := errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid credentials"), "invalid credentials")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	tokenString := authorization[len("Bearer "):]
	if tokenString == "" {
		err := errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid token"), "invalid token")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	token, err := u.service.RefreshToken(reqCtx, requestID.(string), tokenString)
	if err != nil {
		ctx.Error(err)
		ctx.Abort()
		return
	}

	ctx.JSON(http.StatusOK, token)
}
