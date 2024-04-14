package handler

import "github.com/gin-gonic/gin"

type server struct {
	Router *gin.Engine
}

func NewServer() *server {
	return &server{
		Router: gin.Default(),
	}
}
