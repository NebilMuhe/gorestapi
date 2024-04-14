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

// LoginUserHandler implements UserHandler.
func (u *userHandler) LoginUserHandler(ctx *gin.Context) {
	var user service.UserLogin

	if err := ctx.ShouldBindJSON(&user); err != nil {
		err = errors.ErrBadRequest.Wrap(err, "invalid input")
		ctx.Error(err)
		ctx.Abort()
		return
	}

	token, err := u.service.LoginUser(ctx, user)

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

	// Proceed with token validation or processing

	// authorization := ctx.Request.Header.Get("Authorization")
	// tokenString := authorization[len("Bearer "):]

	// fmt.Println(tokenString)
	// if tokenString == "" {
	// 	err := errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid credentials"), "invalid credentials")
	// 	ctx.Error(err)
	// 	ctx.Abort()
	// 	return
	// }
	// secretKey := []byte(os.Getenv("SECRET_KEY"))

	// token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	// 	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	// 		// return nil, errorx.Decorate(fmt.Errorf("unexpected signing method: %v", token.Header["alg"]), "invalid header")
	// 		return nil, errorx.Decorate(errorx.IllegalState.New("unexpected signing method: %v", token.Header["alg"]), "invalid header")
	// 	}

	// 	return secretKey, nil
	// })

	// if err != nil {
	// 	errorRes := ErrorResponse{ErrorType: "UNABLE_TO_READ", Status: http.StatusInternalServerError, Err: err}
	// 	ctx.Error(&errorRes)
	// 	ctx.Abort()
	// 	return
	// }

	// var username string
	// var id string
	// if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
	// 	if int(claims["sub"].(float64)) == 1 {
	// 		id = claims["id"].(string)
	// 		username = claims["username"].(string)
	// 	}
	// }

	// ctx.Set("id", id)

	// newToken, err := data.db.Refresh(ctx, username, tokenString)

	// if err != nil {
	// 	errorRes := ErrorResponse{ErrorType: "UNABLE_TO_READ", Status: http.StatusBadRequest, Err: err}
	// 	ctx.Error(&errorRes)
	// 	ctx.Abort()
	// 	return
	// }

	// ctx.JSON(http.StatusOK, newToken)
}
