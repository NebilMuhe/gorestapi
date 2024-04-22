package main

import (
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/handler"
	"gitlab.com/Nebil/service"
)

func main() {
	logger := service.New()

	err := service.LoadEnv()
	if err != nil {
		log.Println(err)
		return
	}

	DB_DRIVER := os.Getenv("DB_DRIVER")
	DB_URI := os.Getenv("DB_URI")
	PORT := os.Getenv("PORT")

	db, err := data.ConnectDB(DB_DRIVER, DB_URI)
	if err != nil {
		log.Println(err)
		return
	}
	defer db.Close()

	repo := data.NewUserRepository(db, logger)
	service := service.NewUserService(repo, logger)
	handlers := handler.NewUserHandler(service, logger)

	router := handler.NewServer()
	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))

	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)
	router.Router.Run(":" + PORT)

}
