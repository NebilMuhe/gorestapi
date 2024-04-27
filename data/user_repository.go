package data

import (
	"context"

	"github.com/jackc/pgx/v5"
	db "gitlab.com/Nebil/db/sqlc"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/models"
	"gitlab.com/Nebil/utils"
	"go.uber.org/zap"
)

type userRepository struct {
	Database *pgx.Conn
	queries  *db.Queries
	logger   utils.Logger
}
type UserRepository interface {
	Register(context.Context, *models.User) (*models.User, error)
	Login(context.Context, *models.UserLogin) (*models.UserLogin, error)
	Refresh(ctx context.Context, username, refresh_token string) (*models.RefToken, error)
	IsExists(context.Context, *models.User) (bool, error)
	IsLoggedIn(ctx context.Context, username string) (bool, error)
	CheckToken(ctx context.Context, username string) (string, error)
	UpdateToken(ctx context.Context, token, username string) (*models.RefToken, error)
}

func NewUserRepository(database *pgx.Conn, logger utils.Logger) UserRepository {
	return &userRepository{
		Database: database,
		queries:  db.New(database),
		logger:   logger,
	}
}

func ConnectDB(url string) (*pgx.Conn, error) {
	// db, err := sql.Open(driver, url)
	db, err := pgx.Connect(context.Background(), url)
	if err != nil {
		return nil, err
	}

	err = db.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return db, nil
}

func NewLogger() *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil
	}
	defer logger.Sync()

	return logger
}

// Register implements service.UserRepository.
func (u *userRepository) Register(ctx context.Context, user *models.User) (*models.User, error) {
	arg := db.RegisterUserParams{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
	}

	usr, err := u.queries.RegisterUser(ctx, arg)

	if err != nil {
		u.logger.Error(ctx, "unable to register", zap.Error(err), zap.String("username", user.Username), zap.String("email", user.Email))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to register")
		return nil, err
	}

	res := &models.User{
		Username: usr.Username,
		Email:    usr.Email,
	}

	return res, nil
}

// IsExists implements service.UserRepository.
func (u *userRepository) IsExists(ctx context.Context, user *models.User) (bool, error) {
	usr, _ := u.queries.FindBYUsername(ctx, user.Username)
	us, _ := u.queries.FindBYEmail(ctx, user.Email)

	if usr.Username == "" && us.Email == "" {
		return false, nil
	}
	err := errors.ErrUserAlreadyExists.Wrap(errors.ErrUserAlreadyExists.New("user already exists"), "user already exists")
	u.logger.Error(ctx, "user already exists", zap.Error(err), zap.String("username", user.Username), zap.String("email", user.Email))
	return true, err
}

// Login implements service.UserRepository.
func (u *userRepository) Login(ctx context.Context, user *models.UserLogin) (*models.UserLogin, error) {
	usr, err := u.queries.FindBYUsername(ctx, user.Username)

	if err != nil {
		u.logger.Error(ctx, "unable to login", zap.Error(err), zap.String("username", user.Username))
		if err == pgx.ErrNoRows {
			err := errors.ErrNotFound.Wrap(err, "invalid credential")
			return nil, err
		}
		return nil, errors.ErrUnableToRead.Wrap(err, "unable to login")
	}

	res := &models.UserLogin{
		ID:       user.ID,
		Username: usr.Username,
		Password: usr.Password,
	}

	return res, nil
}

// Refresh implements service.UserRepository.
func (u *userRepository) Refresh(ctx context.Context, username string, refresh_token string) (*models.RefToken, error) {
	arg := db.CreateSessionParams{
		Username:     username,
		RefreshToken: refresh_token,
	}
	session, err := u.queries.CreateSession(ctx, arg)
	if err != nil {
		u.logger.Error(ctx, "unable to store refresh token", zap.Error(err), zap.String("username", username))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to store refresh token")
		return nil, err
	}

	res := &models.RefToken{
		// ID:            session.ID,
		Username:      session.Username,
		Refresh_Token: session.RefreshToken,
	}

	return res, nil
}

// IsLoggedIn implements service.UserRepository.
func (u *userRepository) IsLoggedIn(ctx context.Context, username string) (bool, error) {
	session, _ := u.queries.IsLoggedIn(ctx, username)
	if session.Username == "" {
		return false, nil
	}
	err := errors.ErrUserAlreadyLoggedIn.Wrap(errors.ErrUserAlreadyLoggedIn.New("user already logged in"), "user already logged in")
	u.logger.Error(ctx, "user already logged in", zap.Error(err), zap.String("username", username))
	return true, err
}

// CheckToken implements service.UserRepository.
func (u *userRepository) CheckToken(ctx context.Context, username string) (string, error) {
	session, err := u.queries.IsLoggedIn(ctx, username)
	if err != nil {
		u.logger.Error(ctx, "invalid token", zap.Error(err), zap.String("username", username))
		err = errors.ErrUnableToFind.Wrap(err, "unable to find")
		return "", err
	}

	return session.RefreshToken, nil
}

// UpdateToken implements service.UserRepository.
func (u *userRepository) UpdateToken(ctx context.Context, token, username string) (*models.RefToken, error) {
	arg := db.UpdateSessionParams{
		Username:     username,
		RefreshToken: token,
	}
	session, err := u.queries.UpdateSession(ctx, arg)
	if err != nil {
		u.logger.Error(ctx, "unable to update refresh token", zap.Error(err), zap.String("username", username))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return nil, err
	}

	return &models.RefToken{
		// ID:            session,
		Username:      session.Username,
		Refresh_Token: session.RefreshToken,
	}, nil
}
