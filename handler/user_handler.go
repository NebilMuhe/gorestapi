package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
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
	logger  zap.Logger
}

func NewServer() *server {
	return &server{
		Router: gin.Default(),
	}
}

func NewUserHandler(service service.UserService, logger zap.Logger) UserHandler {
	return &userHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterUserHandler implements UserHandler.
func (u *userHandler) RegisterUserHandler(ctx *gin.Context) {
	us := make(chan service.User)
	errChan := make(chan error)
	go func() {
		var user service.User
		reqCtx := ctx.Request.Context()
		requestID, _ := ctx.Get("requestID")

		if err := ctx.ShouldBindJSON(&user); err != nil {
			u.logger.Error("invalid input", zap.Error(err))
			err = errors.ErrBadRequest.Wrap(err, "invalid input")
			errChan <- err
			return
		}

		registeredUser, err := u.service.RegisterUser(reqCtx, requestID.(string), user)
		if err != nil {
			errChan <- err
			return
		}
		us <- *registeredUser
	}()

	select {
	case <-ctx.Request.Context().Done():
		err := ctx.Err()
		u.logger.Error("request timeout", zap.Error(err))
		err = errors.ErrRequestTimeout.Wrap(err, "request timeout")
		ctx.Error(err)
		ctx.Abort()
	case err := <-errChan:
		ctx.Error(err)
		ctx.Abort()
	case res := <-us:
		ctx.JSON(http.StatusCreated, res)
	}
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
