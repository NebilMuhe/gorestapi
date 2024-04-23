package main

import (
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/handler"
	"gitlab.com/Nebil/helpers"
	"gitlab.com/Nebil/service"
)

func setupRouter() (*gin.Engine, *sql.DB, error) {
	logger := helpers.NewLogger()

	err := helpers.LoadEnv()
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	DB_DRIVER := os.Getenv("DB_DRIVER")
	DB_URI := os.Getenv("DB_URI")

	db, err := data.ConnectDB(DB_DRIVER, DB_URI)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	repo := data.NewUserRepository(db, logger)
	service := service.NewUserService(repo, logger)
	handlers := handler.NewUserHandler(service, logger)
	router := handler.NewServer()

	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)

	return router.Router, db, nil
}

func main() {
	router, db, err := setupRouter()
	if err != nil {
		return
	}

	PORT := os.Getenv("PORT")
	defer db.Close()

	if err := router.Run(":" + PORT); err != nil {
		log.Fatal(err)
	}
}
