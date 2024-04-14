package main

import (
	"log"
	"os"

	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Println(err)
		return
	}
	defer logger.Sync()

	err = service.LoadEnv()
	if err != nil {
		log.Println(err)
		return
	}

	DB_DRIVER := os.Getenv("DB_DRIVER")
	DB_URI := os.Getenv("DB_URI")

	db, err := data.ConnectDB(DB_DRIVER, DB_URI)
	if err != nil {
		log.Println(err)
		return
	}
	defer db.Close()
}
