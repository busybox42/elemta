package antivirus

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockScanner implements Scanner interface for testing
type MockScanner struct {
	name       string
	scanType   string
	connected  bool
	scanResult *ScanResult
	scanError  error
}

func NewMockScanner(name string) *MockScanner {
	return &MockScanner{
		name:      name,
		scanType:  "mock",
		connected: false,
	}
}

func (m *MockScanner) Connect() error {
	m.connected = true
	return nil
}

func (m *MockScanner) Close() error {
	m.connected = false
	return nil
}

func (m *MockScanner) IsConnected() bool {
	return m.connected
}

func (m *MockScanner) Name() string {
	return m.name
}

func (m *MockScanner) Type() string {
	return m.scanType
}

func (m *MockScanner) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}
	if m.scanError != nil {
		return nil, m.scanError
	}
	if m.scanResult != nil {
		return m.scanResult, nil
	}
	return &ScanResult{
		Engine:     m.name,
		Timestamp:  time.Now(),
		Clean:      true,
		Infections: []string{},
		Details:    make(map[string]interface{}),
	}, nil
}

func (m *MockScanner) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return m.ScanBytes(ctx, data)
}

func (m *MockScanner) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}
	if m.scanError != nil {
		return nil, m.scanError
	}
	return &ScanResult{
		Engine:     m.name,
		Timestamp:  time.Now(),
		Clean:      true,
		Infections: []string{},
		Details:    map[string]interface{}{"file": filePath},
	}, nil
}

func TestNewManager(t *testing.T) {
	manager := NewManager()
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.scanners)
	assert.Empty(t, manager.scanners)
}

func TestManagerRegister(t *testing.T) {
	manager := NewManager()

	t.Run("Register scanner", func(t *testing.T) {
		scanner := NewMockScanner("test-scanner")
		err := manager.Register(scanner)
		assert.NoError(t, err)

		retrieved, err := manager.Get("test-scanner")
		assert.NoError(t, err)
		assert.Equal(t, scanner, retrieved)
	})

	t.Run("Register duplicate fails", func(t *testing.T) {
		scanner1 := NewMockScanner("duplicate")
		scanner2 := NewMockScanner("duplicate")

		err := manager.Register(scanner1)
		require.NoError(t, err)

		err = manager.Register(scanner2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("Register multiple scanners", func(t *testing.T) {
		mgr := NewManager()
		for i := 0; i < 5; i++ {
			scanner := NewMockScanner("scanner-" + string(rune(48+i)))
			err := mgr.Register(scanner)
			assert.NoError(t, err)
		}

		scanners := mgr.List()
		assert.Len(t, scanners, 5)
	})
}

func TestManagerGet(t *testing.T) {
	manager := NewManager()
	scanner := NewMockScanner("findme")
	manager.Register(scanner)

	t.Run("Get existing scanner", func(t *testing.T) {
		retrieved, err := manager.Get("findme")
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
		assert.Equal(t, "findme", retrieved.Name())
	})

	t.Run("Get non-existent scanner", func(t *testing.T) {
		retrieved, err := manager.Get("not-here")
		assert.ErrorIs(t, err, ErrNotFound)
		assert.Nil(t, retrieved)
	})
}

func TestManagerRemove(t *testing.T) {
	manager := NewManager()

	t.Run("Remove connected scanner", func(t *testing.T) {
		scanner := NewMockScanner("connected-scanner")
		scanner.Connect()
		manager.Register(scanner)

		err := manager.Remove("connected-scanner")
		assert.NoError(t, err)

		_, err = manager.Get("connected-scanner")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Remove disconnected scanner", func(t *testing.T) {
		scanner := NewMockScanner("disconnected-scanner")
		manager.Register(scanner)

		err := manager.Remove("disconnected-scanner")
		assert.NoError(t, err)
	})

	t.Run("Remove non-existent scanner", func(t *testing.T) {
		err := manager.Remove("not-exist")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestManagerCloseAll(t *testing.T) {
	t.Run("Close all scanners", func(t *testing.T) {
		manager := NewManager()

		for i := 0; i < 3; i++ {
			scanner := NewMockScanner("close-" + string(rune(48+i)))
			scanner.Connect()
			manager.Register(scanner)
		}

		err := manager.CloseAll()
		assert.NoError(t, err)

		// Verify all are closed
		for _, scanner := range manager.List() {
			assert.False(t, scanner.IsConnected())
		}
	})

	t.Run("Close empty manager", func(t *testing.T) {
		manager := NewManager()
		err := manager.CloseAll()
		assert.NoError(t, err)
	})
}

func TestManagerScanBytes(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	t.Run("Scan with connected scanner", func(t *testing.T) {
		scanner := NewMockScanner("clean-scanner")
		scanner.Connect()
		manager.Register(scanner)

		results, err := manager.ScanBytes(ctx, []byte("test data"))
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.True(t, results[0].Clean)
	})

	t.Run("Scan with multiple scanners", func(t *testing.T) {
		mgr := NewManager()

		scanner1 := NewMockScanner("scanner1")
		scanner1.Connect()
		mgr.Register(scanner1)

		scanner2 := NewMockScanner("scanner2")
		scanner2.Connect()
		mgr.Register(scanner2)

		results, err := mgr.ScanBytes(ctx, []byte("test"))
		assert.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("Scan with disconnected scanner", func(t *testing.T) {
		mgr := NewManager()
		scanner := NewMockScanner("disconnected")
		// Don't connect
		mgr.Register(scanner)

		results, err := mgr.ScanBytes(ctx, []byte("test"))
		assert.ErrorIs(t, err, ErrScanFailed)
		assert.Nil(t, results)
	})

	t.Run("Scan with scanner error", func(t *testing.T) {
		mgr := NewManager()
		scanner := NewMockScanner("error-scanner")
		scanner.Connect()
		scanner.scanError = errors.New("scan error")
		mgr.Register(scanner)

		results, err := mgr.ScanBytes(ctx, []byte("test"))
		assert.ErrorIs(t, err, ErrScanFailed)
		assert.Nil(t, results)
	})

	t.Run("Scan with infection found", func(t *testing.T) {
		mgr := NewManager()
		scanner := NewMockScanner("virus-finder")
		scanner.Connect()
		scanner.scanResult = &ScanResult{
			Engine:     "virus-finder",
			Timestamp:  time.Now(),
			Clean:      false,
			Infections: []string{"Trojan.Test", "Malware.Generic"},
		}
		mgr.Register(scanner)

		results, err := mgr.ScanBytes(ctx, []byte("malicious data"))
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.False(t, results[0].Clean)
		assert.Len(t, results[0].Infections, 2)
	})
}

func TestManagerScanReader(t *testing.T) {
	manager := NewManager()
	scanner := NewMockScanner("reader-scanner")
	scanner.Connect()
	manager.Register(scanner)

	ctx := context.Background()

	t.Run("Scan reader successfully", func(t *testing.T) {
		reader := strings.NewReader("test data from reader")
		results, err := manager.ScanReader(ctx, reader)
		assert.NoError(t, err)
		assert.Len(t, results, 1)
	})

	t.Run("Scan empty reader", func(t *testing.T) {
		reader := strings.NewReader("")
		results, err := manager.ScanReader(ctx, reader)
		assert.NoError(t, err)
		assert.Len(t, results, 1)
	})
}

func TestManagerScanFile(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	t.Run("Scan file with connected scanner", func(t *testing.T) {
		scanner := NewMockScanner("file-scanner")
		scanner.Connect()
		manager.Register(scanner)

		results, err := manager.ScanFile(ctx, "/tmp/test.txt")
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Contains(t, results[0].Details, "file")
	})

	t.Run("Scan file with disconnected scanner", func(t *testing.T) {
		mgr := NewManager()
		scanner := NewMockScanner("disconnected-file")
		mgr.Register(scanner)

		results, err := mgr.ScanFile(ctx, "/tmp/test.txt")
		assert.ErrorIs(t, err, ErrScanFailed)
		assert.Nil(t, results)
	})
}

func TestCacheFactory(t *testing.T) {
	t.Run("Create ClamAV scanner", func(t *testing.T) {
		config := Config{
			Type:    "clamav",
			Name:    "test-clamav",
			Address: "localhost:3310",
		}

		scanner, err := Factory(config)
		require.NoError(t, err)
		assert.NotNil(t, scanner)
		assert.Equal(t, "clamav", scanner.Type())
	})

	t.Run("Unsupported scanner type", func(t *testing.T) {
		config := Config{
			Type: "unsupported",
			Name: "test",
		}

		scanner, err := Factory(config)
		assert.Error(t, err)
		assert.Nil(t, scanner)
		assert.Contains(t, err.Error(), "unsupported scanner type")
	})
}

func TestScanResult(t *testing.T) {
	t.Run("Clean scan result", func(t *testing.T) {
		result := &ScanResult{
			Engine:     "test-engine",
			Timestamp:  time.Now(),
			Clean:      true,
			Infections: []string{},
			Score:      0.0,
			Details:    make(map[string]interface{}),
		}

		assert.True(t, result.Clean)
		assert.Empty(t, result.Infections)
		assert.Equal(t, "test-engine", result.Engine)
	})

	t.Run("Infected scan result", func(t *testing.T) {
		result := &ScanResult{
			Engine:    "test-engine",
			Timestamp: time.Now(),
			Clean:     false,
			Infections: []string{
				"Win32.Trojan",
				"JS.Malware",
				"PDF.Exploit",
			},
			Score: 95.5,
			Details: map[string]interface{}{
				"signature_count": 3,
				"threat_level":    "high",
			},
		}

		assert.False(t, result.Clean)
		assert.Len(t, result.Infections, 3)
		assert.Equal(t, 95.5, result.Score)
		assert.Equal(t, 3, result.Details["signature_count"])
	})

	t.Run("Scan result with details", func(t *testing.T) {
		result := &ScanResult{
			Engine:    "detailed-scanner",
			Timestamp: time.Now(),
			Clean:     true,
			Details: map[string]interface{}{
				"scan_duration_ms": 123,
				"bytes_scanned":    1024,
				"signatures_used":  "latest",
			},
		}

		assert.Equal(t, 123, result.Details["scan_duration_ms"])
		assert.Equal(t, 1024, result.Details["bytes_scanned"])
	})
}

func TestErrors(t *testing.T) {
	t.Run("Error constants", func(t *testing.T) {
		assert.Equal(t, "scanner not found", ErrNotFound.Error())
		assert.Equal(t, "not connected to scanner", ErrNotConnected.Error())
		assert.Equal(t, "scan failed", ErrScanFailed.Error())
	})

	t.Run("Error types are distinct", func(t *testing.T) {
		assert.NotEqual(t, ErrNotFound, ErrNotConnected)
		assert.NotEqual(t, ErrNotFound, ErrScanFailed)
		assert.NotEqual(t, ErrNotConnected, ErrScanFailed)
	})
}

func TestManagerList(t *testing.T) {
	manager := NewManager()

	scanners := []string{"scanner1", "scanner2", "scanner3"}
	for _, name := range scanners {
		scanner := NewMockScanner(name)
		manager.Register(scanner)
	}

	list := manager.List()
	assert.Len(t, list, 3)
	for _, name := range scanners {
		assert.Contains(t, list, name)
	}
}

func TestConfig(t *testing.T) {
	t.Run("Basic config", func(t *testing.T) {
		config := Config{
			Type:    "clamav",
			Name:    "test",
			Address: "localhost:3310",
			Options: map[string]interface{}{
				"timeout": 30,
				"retry":   3,
			},
		}

		assert.Equal(t, "clamav", config.Type)
		assert.Equal(t, "test", config.Name)
		assert.Equal(t, "localhost:3310", config.Address)
		assert.Equal(t, 30, config.Options["timeout"])
	})

	t.Run("Empty config", func(t *testing.T) {
		config := Config{}
		assert.Empty(t, config.Type)
		assert.Empty(t, config.Name)
		assert.Nil(t, config.Options)
	})
}

func TestManagerConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency tests in short mode")
	}

	manager := NewManager()

	t.Run("Concurrent Register", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				scanner := NewMockScanner("concurrent-" + string(rune(48+idx)))
				manager.Register(scanner)
			}(i)
		}
		wg.Wait()

		list := manager.List()
		assert.Equal(t, 50, len(list))
	})

	t.Run("Concurrent Get", func(t *testing.T) {
		scanner := NewMockScanner("shared")
		manager.Register(scanner)

		var wg sync.WaitGroup
		for i := 0; i < 1000; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.Get("shared")
			}()
		}
		wg.Wait()
	})
}

func TestScannerIntegration(t *testing.T) {
	ctx := context.Background()

	t.Run("Full scan workflow", func(t *testing.T) {
		manager := NewManager()

		// Register and connect scanner
		scanner := NewMockScanner("workflow-scanner")
		err := manager.Register(scanner)
		require.NoError(t, err)

		err = scanner.Connect()
		require.NoError(t, err)
		assert.True(t, scanner.IsConnected())

		// Scan data
		results, err := manager.ScanBytes(ctx, []byte("test data"))
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.True(t, results[0].Clean)

		// Close scanner
		err = scanner.Close()
		assert.NoError(t, err)
		assert.False(t, scanner.IsConnected())
	})

	t.Run("Scan with infection", func(t *testing.T) {
		manager := NewManager()
		scanner := NewMockScanner("infection-scanner")
		scanner.Connect()
		scanner.scanResult = &ScanResult{
			Engine:     "infection-scanner",
			Timestamp:  time.Now(),
			Clean:      false,
			Infections: []string{"EICAR-Test-File"},
			Score:      100.0,
		}
		manager.Register(scanner)

		results, err := manager.ScanBytes(ctx, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"))
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.False(t, results[0].Clean)
		assert.Contains(t, results[0].Infections, "EICAR-Test-File")
	})
}

func BenchmarkManagerRegister(b *testing.B) {
	manager := NewManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner := NewMockScanner("bench-scanner-" + string(rune(i)))
		manager.Register(scanner)
	}
}

func BenchmarkManagerGet(b *testing.B) {
	manager := NewManager()
	scanner := NewMockScanner("bench")
	manager.Register(scanner)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Get("bench")
	}
}

func BenchmarkScanBytes(b *testing.B) {
	manager := NewManager()
	scanner := NewMockScanner("bench-scanner")
	scanner.Connect()
	manager.Register(scanner)

	ctx := context.Background()
	data := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ScanBytes(ctx, data)
	}
}

