package data

import (
	"context"
	"database/sql"

	db "gitlab.com/Nebil/db/sqlc"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

type userRepository struct {
	Database *sql.DB
	queries  *db.Queries
	logger   zap.Logger
}

func NewUserRepository(database *sql.DB, logger zap.Logger) service.UserRepository {
	return &userRepository{
		Database: database,
		queries:  db.New(database),
		logger:   logger,
	}
}

func ConnectDB(driver, url string) (*sql.DB, error) {
	db, err := sql.Open(driver, url)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Register implements service.UserRepository.
func (u *userRepository) Register(ctx context.Context, user *service.User) (*service.User, error) {
	arg := db.RegisterUserParams{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
	}

	usr, err := u.queries.RegisterUser(ctx, arg)

	if err != nil {
		u.logger.Error("unable to register", zap.Error(err))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to register")
		return nil, err
	}

	res := &service.User{
		Username: usr.Username,
		Email:    usr.Email,
	}

	return res, nil
}

func NewLogger() *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil
	}
	defer logger.Sync()

	return logger
}

// IsExists implements service.UserRepository.
func (u *userRepository) IsExists(ctx context.Context, user *service.User) (bool, error) {
	log := NewLogger()
	usr, _ := u.queries.FindBYUsername(ctx, user.Username)
	us, _ := u.queries.FindBYEmail(ctx, user.Email)

	if usr.Username == "" && us.Email == "" {
		return false, nil
	}
	err := errors.ErrUserAlreadyExists.Wrap(errors.ErrUserAlreadyExists.New("user already exists"), "user already exists")
	log.Error("user already exists", zap.Error(err))
	return true, err
}

// Login implements service.UserRepository.
func (u *userRepository) Login(ctx context.Context, user *service.UserLogin) (*service.UserLogin, error) {
	// errChan := make(chan error)
	// resChan := make(chan *service.UserLogin)
	// go func() {
	// 	usr, err := u.queries.FindBYUsername(ctx, user.Username)
	// 	if err != nil {
	// 		errChan <- err
	// 		return
	// 	}

	// 	resChan <- &service.UserLogin{
	// 		ID:       usr.ID.String(),
	// 		Username: usr.Username,
	// 		Password: usr.Password,
	// 	}
	// }()

	// select {
	// case <-ctx.Done():
	// 	err := ctx.Err()
	// 	return nil, err
	// case err := <-errChan:
	// 	return nil, err
	// case usr := <-resChan:
	// 	return usr, nil
	// }
	usr, err := u.queries.FindBYUsername(ctx, user.Username)
	if err != nil {
		u.logger.Error("unable to login", zap.Error(err))
		if err == sql.ErrNoRows {
			err := errors.ErrNotFound.Wrap(err, "not found")
			return nil, err
		}
		return nil, errors.ErrUnableToRead.Wrap(err, "unable to login")
	}

	res := &service.UserLogin{
		ID:       usr.ID.String(),
		Username: usr.Username,
		Password: usr.Password,
	}

	return res, nil
}

// Refresh implements service.UserRepository.
func (u *userRepository) Refresh(ctx context.Context, username string, refresh_token string) (*service.RefToken, error) {
	// errChan := make(chan error)
	// resChan := make(chan *service.RefToken)

	// go func() {
	// 	arg := db.CreateSessionParams{
	// 		Username:     username,
	// 		RefreshToken: refresh_token,
	// 	}
	// 	session, err := u.queries.CreateSession(ctx, arg)
	// 	if err != nil {
	// 		errChan <- err
	// 		return
	// 	}

	// 	resChan <- &service.RefToken{
	// 		ID:            session.ID.String(),
	// 		Username:      session.Username,
	// 		Refresh_Token: session.RefreshToken,
	// 		IsUsed:        session.IsUsed.Bool,
	// 	}
	// }()

	// select {
	// case <-ctx.Done():
	// 	err := ctx.Err()
	// 	return nil, err
	// case err := <-errChan:
	// 	return nil, err
	// case res := <-resChan:
	// 	return res, nil
	// }

	arg := db.CreateSessionParams{
		Username:     username,
		RefreshToken: refresh_token,
	}
	session, err := u.queries.CreateSession(ctx, arg)
	if err != nil {
		u.logger.Error("unable to store refresh token", zap.Error(err))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to store refresh token")
		return nil, err
	}

	res := &service.RefToken{
		ID:            session.ID.String(),
		Username:      session.Username,
		Refresh_Token: session.RefreshToken,
		IsUsed:        session.IsUsed.Bool,
	}

	return res, nil
}

// IsLoggedIn implements service.UserRepository.
func (u *userRepository) IsLoggedIn(ctx context.Context, username string) (bool, error) {
	session, _ := u.queries.IsLoggedIn(ctx, username)
	if session.Username == "" {
		return false, nil
	}
	return true, errors.ErrUserAlreadyLoggedIn.Wrap(errors.ErrUserAlreadyLoggedIn.New("user already logged in"), "user already logged in")
}

// CheckToken implements service.UserRepository.
func (u *userRepository) CheckToken(ctx context.Context, username string) (string, error) {
	session, err := u.queries.IsLoggedIn(ctx, username)
	if err != nil {
		u.logger.Error("invalid token", zap.Error(err))
		err = errors.ErrUnableToFind.Wrap(err, "unable to find")
		return "", err
	}

	return session.RefreshToken, nil
}

// UpdateToken implements service.UserRepository.
func (u *userRepository) UpdateToken(ctx context.Context, token, username string) (*service.RefToken, error) {
	arg := db.UpdateSessionParams{
		Username:     username,
		RefreshToken: token,
	}
	session, err := u.queries.UpdateSession(ctx, arg)
	if err != nil {
		u.logger.Error("unable to update refresh token", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return nil, err
	}

	return &service.RefToken{
		ID:            session.ID.String(),
		Username:      session.Username,
		Refresh_Token: session.RefreshToken,
		IsUsed:        session.IsUsed.Bool,
	}, nil
}
