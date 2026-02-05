package metrics

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// DeliveryMetrics holds delivery statistics
type DeliveryMetrics struct {
	TotalDelivered int64     `json:"total_delivered"`
	TotalFailed    int64     `json:"total_failed"`
	TotalDeferred  int64     `json:"total_deferred"`
	TotalReceived  int64     `json:"total_received"`
	LastUpdated    time.Time `json:"last_updated"`
}

// HourlyStats holds hourly delivery counts
type HourlyStats struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// ValkeyStore provides metrics storage using Valkey
type ValkeyStore struct {
	client valkey.Client
	prefix string
}

// NewValkeyStore creates a new Valkey-backed metrics store
func NewValkeyStore(addr string) (*ValkeyStore, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
	})
	if err != nil {
		return nil, err
	}

	return &ValkeyStore{
		client: client,
		prefix: "elemta:metrics:",
	}, nil
}

// Close closes the Valkey connection
func (s *ValkeyStore) Close() {
	s.client.Close()
}

// incrCounter is a helper to increment a metric counter with hourly tracking
func (s *ValkeyStore) incrCounter(ctx context.Context, counterName string) error {
	key := s.prefix + counterName
	hourKey := s.prefix + "hourly:" + time.Now().Format("2006-01-02:15") + ":" + counterName

	cmds := []valkey.Completed{
		s.client.B().Incr().Key(key).Build(),
		s.client.B().Incr().Key(hourKey).Build(),
		s.client.B().Expire().Key(hourKey).Seconds(86400).Build(), // 24h TTL
		s.client.B().Set().Key(s.prefix + "last_updated").Value(time.Now().Format(time.RFC3339)).Build(),
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// IncrDelivered increments the delivered counter
func (s *ValkeyStore) IncrDelivered(ctx context.Context) error {
	return s.incrCounter(ctx, "delivered")
}

// IncrFailed increments the failed counter
func (s *ValkeyStore) IncrFailed(ctx context.Context) error {
	return s.incrCounter(ctx, "failed")
}

// IncrDeferred increments the deferred counter
func (s *ValkeyStore) IncrDeferred(ctx context.Context) error {
	return s.incrCounter(ctx, "deferred")
}

// IncrReceived increments the received counter
func (s *ValkeyStore) IncrReceived(ctx context.Context) error {
	key := s.prefix + "received"

	cmds := []valkey.Completed{
		s.client.B().Incr().Key(key).Build(),
		s.client.B().Set().Key(s.prefix + "last_updated").Value(time.Now().Format(time.RFC3339)).Build(),
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetMetrics retrieves current delivery metrics
func (s *ValkeyStore) GetMetrics(ctx context.Context) (*DeliveryMetrics, error) {
	metrics := &DeliveryMetrics{}

	// Get counters
	delivered, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"delivered").Build()).ToString()
	failed, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"failed").Build()).ToString()
	deferred, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"deferred").Build()).ToString()
	received, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"received").Build()).ToString()
	lastUpdated, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"last_updated").Build()).ToString()

	metrics.TotalDelivered, _ = strconv.ParseInt(delivered, 10, 64)
	metrics.TotalFailed, _ = strconv.ParseInt(failed, 10, 64)
	metrics.TotalDeferred, _ = strconv.ParseInt(deferred, 10, 64)
	metrics.TotalReceived, _ = strconv.ParseInt(received, 10, 64)
	metrics.LastUpdated, _ = time.Parse(time.RFC3339, lastUpdated)

	return metrics, nil
}

// GetHourlyStats retrieves hourly statistics for the last 24 hours
func (s *ValkeyStore) GetHourlyStats(ctx context.Context) ([]HourlyStats, error) {
	stats := make([]HourlyStats, 24)
	now := time.Now()

	for i := 0; i < 24; i++ {
		hour := now.Add(-time.Duration(23-i) * time.Hour)
		hourStr := hour.Format("2006-01-02:15")
		displayHour := hour.Format("15:00")

		delivered, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":delivered").Build()).ToString()
		failed, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":failed").Build()).ToString()
		deferred, _ := s.client.Do(ctx, s.client.B().Get().Key(s.prefix+"hourly:"+hourStr+":deferred").Build()).ToString()

		stats[i] = HourlyStats{
			Hour: displayHour,
		}
		stats[i].Delivered, _ = strconv.ParseInt(delivered, 10, 64)
		stats[i].Failed, _ = strconv.ParseInt(failed, 10, 64)
		stats[i].Deferred, _ = strconv.ParseInt(deferred, 10, 64)
	}

	return stats, nil
}

// AddRecentError stores a recent delivery error
func (s *ValkeyStore) AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error {
	errorData := map[string]string{
		"message_id": messageID,
		"recipient":  recipient,
		"error":      errorMsg,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(errorData)
	if err != nil {
		return err
	}

	key := s.prefix + "recent_errors"
	cmds := []valkey.Completed{
		s.client.B().Lpush().Key(key).Element(string(data)).Build(),
		s.client.B().Ltrim().Key(key).Start(0).Stop(99).Build(), // Keep last 100 errors
	}

	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetRecentErrors retrieves recent delivery errors
func (s *ValkeyStore) GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error) {
	key := s.prefix + "recent_errors"
	result, err := s.client.Do(ctx, s.client.B().Lrange().Key(key).Start(0).Stop(limit-1).Build()).AsStrSlice()
	if err != nil {
		return nil, err
	}

	errors := make([]map[string]string, 0, len(result))
	for _, item := range result {
		var errorData map[string]string
		if err := json.Unmarshal([]byte(item), &errorData); err != nil {
			continue
		}
		errors = append(errors, errorData)
	}

	return errors, nil
}
