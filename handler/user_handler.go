package handler

import (
	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/service"
)

type server struct {
	Router *gin.Engine
}

type UserHandler interface {
	RegisterUserHandler(ctx *gin.Context)
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

}
