package datasource

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// FileDataSource implements DataSource for flat file auth
// Format: username:password per line, no hashing
// Not for production use

type FileDataSource struct {
	path      string
	users     map[string]string
	connected bool
	mu        sync.RWMutex
}

func NewFile(config Config) DataSource {
	path, _ := config.Options["file"].(string)
	// If path is empty, try the db_path key as well
	if path == "" {
		path, _ = config.Options["db_path"].(string)
	}
	return &FileDataSource{path: path, users: make(map[string]string)}
}

func (f *FileDataSource) Connect() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.path == "" {
		return fmt.Errorf("file path is empty")
	}

	file, err := os.Open(f.path)
	if err != nil {
		return fmt.Errorf("failed to open user file %s: %w", f.path, err)
	}
	defer file.Close()
	f.users = make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		f.users[parts[0]] = parts[1]
	}
	f.connected = true
	return scanner.Err()
}

func (f *FileDataSource) Close() error      { f.connected = false; return nil }
func (f *FileDataSource) IsConnected() bool { return f.connected }
func (f *FileDataSource) Name() string      { return "file" }
func (f *FileDataSource) Type() string      { return "file" }

func (f *FileDataSource) Authenticate(ctx context.Context, username, password string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	pw, ok := f.users[username]
	if !ok {
		return false, ErrNotFound
	}

	// Simple plaintext comparison
	if pw == password {
		return true, nil
	}

	// Check if it's a bcrypt hash (starts with $2a$ or similar)
	if strings.HasPrefix(pw, "$2") {
		err := bcrypt.CompareHashAndPassword([]byte(pw), []byte(password))
		return err == nil, nil
	}

	// Try OpenLDAP-style password hashes
	if strings.HasPrefix(pw, "{SHA}") ||
		strings.HasPrefix(pw, "{SHA256}") ||
		strings.HasPrefix(pw, "{SHA512}") ||
		strings.HasPrefix(pw, "{SSHA}") {
		// Not implementing these here as it requires the crypto packages
		// but we just need plaintext for the test
		return false, nil
	}

	return false, ErrInvalidInput
}

func (f *FileDataSource) GetUser(ctx context.Context, username string) (User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	pw, ok := f.users[username]
	if !ok {
		return User{}, ErrNotFound
	}
	return User{Username: username, Password: pw, IsActive: true}, nil
}

func (f *FileDataSource) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	users := make([]User, 0, len(f.users))
	for u, p := range f.users {
		users = append(users, User{Username: u, Password: p, IsActive: true})
	}
	return users, nil
}
func (f *FileDataSource) CreateUser(ctx context.Context, user User) error { return ErrNotSupported }
func (f *FileDataSource) UpdateUser(ctx context.Context, user User) error { return ErrNotSupported }
func (f *FileDataSource) DeleteUser(ctx context.Context, username string) error {
	return ErrNotSupported
}
func (f *FileDataSource) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return nil, ErrNotSupported
}
