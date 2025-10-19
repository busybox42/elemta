package logging

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevel(t *testing.T) {
	t.Run("Level constants", func(t *testing.T) {
		assert.Equal(t, 0, int(Debug))
		assert.Equal(t, 1, int(Info))
		assert.Equal(t, 2, int(Warn))
		assert.Equal(t, 3, int(Error))
		assert.Equal(t, 4, int(Fatal))
	})

	t.Run("Level String()", func(t *testing.T) {
		assert.Equal(t, "DEBUG", Debug.String())
		assert.Equal(t, "INFO", Info.String())
		assert.Equal(t, "WARN", Warn.String())
		assert.Equal(t, "ERROR", Error.String())
		assert.Equal(t, "FATAL", Fatal.String())
	})

	t.Run("Unknown level", func(t *testing.T) {
		unknown := Level(99)
		assert.Contains(t, unknown.String(), "LEVEL(99)")
	})
}

func TestField(t *testing.T) {
	t.Run("Create field", func(t *testing.T) {
		field := F("key", "value")
		assert.Equal(t, "key", field.Key)
		assert.Equal(t, "value", field.Value)
	})

	t.Run("Field with various types", func(t *testing.T) {
		fields := []Field{
			F("string", "text"),
			F("int", 42),
			F("bool", true),
			F("float", 3.14),
			F("nil", nil),
		}

		assert.Len(t, fields, 5)
		assert.Equal(t, "string", fields[0].Key)
		assert.Equal(t, 42, fields[1].Value)
		assert.True(t, fields[2].Value.(bool))
	})
}

func TestNewManager(t *testing.T) {
	manager := NewManager()

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.loggers)
	assert.NotNil(t, manager.default_)
	assert.Empty(t, manager.loggers)
}

func TestManagerRegister(t *testing.T) {
	manager := NewManager()

	t.Run("Register logger", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "test"})
		err := manager.Register(logger, "test")
		assert.NoError(t, err)

		retrieved, exists := manager.Get("test")
		assert.True(t, exists)
		assert.Equal(t, logger, retrieved)
	})

	t.Run("Register duplicate fails", func(t *testing.T) {
		logger1 := NewConsoleLogger(Config{Name: "dup"})
		logger2 := NewConsoleLogger(Config{Name: "dup"})

		err := manager.Register(logger1, "dup")
		require.NoError(t, err)

		err = manager.Register(logger2, "dup")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("Register multiple loggers", func(t *testing.T) {
		mgr := NewManager()
		for i := 0; i < 5; i++ {
			logger := NewConsoleLogger(Config{Name: "logger-" + string(rune(48+i))})
			err := mgr.Register(logger, "logger-"+string(rune(48+i)))
			assert.NoError(t, err)
		}

		loggers := mgr.List()
		assert.Len(t, loggers, 5)
	})
}

func TestManagerGetAndDefault(t *testing.T) {
	manager := NewManager()

	t.Run("Get default logger", func(t *testing.T) {
		defaultLogger := manager.Default()
		assert.NotNil(t, defaultLogger)
	})

	t.Run("Get existing logger", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "exists"})
		manager.Register(logger, "exists")

		retrieved, exists := manager.Get("exists")
		assert.True(t, exists)
		assert.Equal(t, logger, retrieved)
	})

	t.Run("Get non-existent logger", func(t *testing.T) {
		retrieved, exists := manager.Get("not-here")
		assert.False(t, exists)
		assert.Nil(t, retrieved)
	})
}

func TestManagerSetDefault(t *testing.T) {
	manager := NewManager()

	t.Run("Set default to existing logger", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "new-default"})
		manager.Register(logger, "new-default")

		err := manager.SetDefault("new-default")
		assert.NoError(t, err)

		defaultLogger := manager.Default()
		assert.Equal(t, logger, defaultLogger)
	})

	t.Run("Set default to non-existent logger", func(t *testing.T) {
		err := manager.SetDefault("does-not-exist")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestManagerRemove(t *testing.T) {
	manager := NewManager()

	t.Run("Remove existing logger", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "remove-me"})
		manager.Register(logger, "remove-me")

		err := manager.Remove("remove-me")
		assert.NoError(t, err)

		_, exists := manager.Get("remove-me")
		assert.False(t, exists)
	})

	t.Run("Remove non-existent logger", func(t *testing.T) {
		err := manager.Remove("not-here")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestManagerCloseAll(t *testing.T) {
	t.Run("Close all loggers", func(t *testing.T) {
		manager := NewManager()

		for i := 0; i < 3; i++ {
			logger := NewConsoleLogger(Config{Name: "close-" + string(rune(48+i))})
			manager.Register(logger, "close-"+string(rune(48+i)))
		}

		err := manager.CloseAll()
		assert.NoError(t, err)
	})

	t.Run("Close empty manager", func(t *testing.T) {
		manager := NewManager()
		err := manager.CloseAll()
		assert.NoError(t, err)
	})
}

func TestGlobalManager(t *testing.T) {
	t.Run("Get global manager", func(t *testing.T) {
		manager := GetManager()
		assert.NotNil(t, manager)
	})

	t.Run("Global Default()", func(t *testing.T) {
		logger := Default()
		assert.NotNil(t, logger)
	})

	t.Run("Global Register()", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "global-test"})
		err := Register(logger, "global-test")
		assert.NoError(t, err)

		retrieved, exists := Get("global-test")
		assert.True(t, exists)
		assert.Equal(t, logger, retrieved)

		// Cleanup
		globalManager.Remove("global-test")
	})

	t.Run("Global SetDefault()", func(t *testing.T) {
		logger := NewConsoleLogger(Config{Name: "global-default"})
		Register(logger, "global-default")

		err := SetDefault("global-default")
		assert.NoError(t, err)

		defaultLogger := Default()
		assert.Equal(t, logger, defaultLogger)
	})
}

func TestFactoryFunction(t *testing.T) {
	t.Run("Create console logger", func(t *testing.T) {
		config := Config{
			Type:  "console",
			Name:  "test-console",
			Level: Info,
		}

		logger, err := Factory(config)
		require.NoError(t, err)
		assert.NotNil(t, logger)
	})

	t.Run("Create file logger", func(t *testing.T) {
		tempFile := t.TempDir() + "/test.log"
		config := Config{
			Type:   "file",
			Name:   "test-file",
			Level:  Debug,
			Output: tempFile,
		}

		logger, err := Factory(config)
		if err != nil {
			t.Logf("File logger creation: %v", err)
		} else {
			assert.NotNil(t, logger)
			logger.Close()
		}
	})

	t.Run("Create elastic logger", func(t *testing.T) {
		config := Config{
			Type:   "elastic",
			Name:   "test-elastic",
			Level:  Info,
			Output: "http://localhost:9200",
		}

		logger, err := Factory(config)
		if err != nil {
			t.Logf("Elastic logger creation: %v", err)
		} else {
			assert.NotNil(t, logger)
			logger.Close()
		}
	})

	t.Run("Unsupported logger type", func(t *testing.T) {
		config := Config{
			Type: "unsupported",
			Name: "test",
		}

		logger, err := Factory(config)
		assert.Error(t, err)
		assert.Nil(t, logger)
		assert.Contains(t, err.Error(), "unsupported logger type")
	})
}

func TestConsoleLogger(t *testing.T) {
	var buf bytes.Buffer

	config := Config{
		Type:      "console",
		Name:      "test-console",
		Level:     Debug,
		Formatter: "text",
	}

	logger := NewConsoleLogger(config)
	logger.SetOutput(&buf)

	t.Run("Log messages at different levels", func(t *testing.T) {
		logger.Debug("debug message", F("key", "value"))
		logger.Info("info message", F("count", 42))
		logger.Warn("warn message", F("warning", true))
		logger.Error("error message", F("error", "something failed"))

		output := buf.String()
		assert.Contains(t, output, "debug message")
		assert.Contains(t, output, "info message")
		assert.Contains(t, output, "warn message")
		assert.Contains(t, output, "error message")
	})

	t.Run("Set and get level", func(t *testing.T) {
		logger.SetLevel(Warn)
		assert.Equal(t, Warn, logger.GetLevel())

		logger.SetLevel(Error)
		assert.Equal(t, Error, logger.GetLevel())
	})

	t.Run("WithField and WithFields", func(t *testing.T) {
		derived1 := logger.WithField("session", "abc123")
		assert.NotNil(t, derived1)

		derived2 := logger.WithFields(
			F("user", "admin"),
			F("action", "login"),
		)
		assert.NotNil(t, derived2)
	})

	t.Run("Close logger", func(t *testing.T) {
		err := logger.Close()
		assert.NoError(t, err)
	})
}

func BenchmarkLoggerCreation(b *testing.B) {
	config := Config{
		Type:  "console",
		Name:  "bench",
		Level: Info,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewConsoleLogger(config)
	}
}

func BenchmarkFieldCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = F("key", "value")
	}
}

