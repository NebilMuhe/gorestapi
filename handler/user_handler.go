package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/models"
	"gitlab.com/Nebil/service"
	"gitlab.com/Nebil/utils"
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
	logger  utils.Logger
}

func NewServer() *server {
	return &server{
		Router: gin.Default(),
	}
}

func NewUserHandler(service service.UserService, logger utils.Logger) UserHandler {
	return &userHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterUserHandler implements UserHandler.
func (u *userHandler) RegisterUserHandler(ctx *gin.Context) {
	us := make(chan models.User)
	errChan := make(chan error)
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")
	contx := context.WithValue(reqCtx, "requestID", requestID)
	go func() {
		var user models.User
		if err := ctx.ShouldBindJSON(&user); err != nil {
			u.logger.Error(contx, "unable to bind", zap.Error(err))
			err = errors.ErrBadRequest.Wrap(err, "unable to bind")
			errChan <- err
			return
		}

		registeredUser, err := u.service.RegisterUser(contx, user)
		if err != nil {
			errChan <- err
			return
		}
		us <- *registeredUser
	}()

	select {
	case <-ctx.Request.Context().Done():
		err := ctx.Err()
		u.logger.Error(contx, "request timeout", zap.Error(err))
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
	response := make(chan map[string]string)
	errChan := make(chan error)
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")
	contx := context.WithValue(reqCtx, "requestID", requestID)
	go func() {
		var user models.UserLogin
		if err := ctx.ShouldBindJSON(&user); err != nil {
			u.logger.Error(contx, "invalid input", zap.Error(err))
			err = errors.ErrBadRequest.Wrap(err, "invalid input")
			errChan <- err
			return
		}

		token, err := u.service.LoginUser(contx, user)

		if err != nil {
			errChan <- err
			return
		}
		response <- token
	}()

	select {
	case <-ctx.Request.Context().Done():
		err := ctx.Err()
		u.logger.Error(contx, "request timeout", zap.Error(err))
		err = errors.ErrRequestTimeout.Wrap(err, "request timeout")
		ctx.Error(err)
		ctx.Abort()
	case err := <-errChan:
		ctx.Error(err)
		ctx.Abort()
	case res := <-response:
		ctx.JSON(http.StatusOK, res)
	}
}

func (u *userHandler) RefreshTokenHandler(ctx *gin.Context) {
	response := make(chan map[string]string)
	errChan := make(chan error)
	reqCtx := ctx.Request.Context()
	requestID, _ := ctx.Get("requestID")
	contx := context.WithValue(reqCtx, "requestID", requestID)
	go func() {
		authorization := ctx.Request.Header.Get("Authorization")
		if authorization == "" || !strings.HasPrefix(authorization, "Bearer ") {
			err := errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid credentials"), "invalid credentials")
			u.logger.Error(contx, "unauthorized", zap.Error(err))
			errChan <- err
			return
		}

		tokenString := authorization[len("Bearer "):]
		if tokenString == "" {
			err := errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid token"), "invalid token")
			u.logger.Error(contx, "unauthorized", zap.Error(err))
			errChan <- err
			return
		}

		token, err := u.service.RefreshToken(contx, tokenString)
		if err != nil {
			errChan <- err
			return
		}

		response <- token
	}()

	select {
	case <-ctx.Request.Context().Done():
		err := ctx.Err()
		u.logger.Error(contx, "request timeout", zap.Error(err))
		err = errors.ErrRequestTimeout.Wrap(err, "request timeout")
		ctx.Error(err)
		ctx.Abort()
	case err := <-errChan:
		ctx.Error(err)
		ctx.Abort()
	case res := <-response:
		ctx.JSON(http.StatusOK, res)
	}
}
