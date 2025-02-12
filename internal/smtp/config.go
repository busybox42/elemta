package smtp

import (
    "encoding/json"
    "fmt"
    "os"
)

type Config struct {
    ListenAddr    string   `json:"listen_addr"`
    QueueDir      string   `json:"queue_dir"`
    MaxSize       int64    `json:"max_size"`
    DevMode       bool     `json:"dev_mode"`
    AllowedRelays []string `json:"allowed_relays"`
    Hostname      string   `json:"hostname"`
    MaxWorkers    int      `json:"max_workers"`
    MaxRetries    int      `json:"max_retries"`
    MaxQueueTime  int      `json:"max_queue_time"`
    RetrySchedule []int    `json:"retry_schedule"`
}

func findConfigFile(configPath string) (string, error) {
    if configPath != "" {
        if _, err := os.Stat(configPath); err == nil {
            fmt.Printf("Using config from explicit path: %s\n", configPath)
            return configPath, nil
        }
        return "", fmt.Errorf("config file not found at %s", configPath)
    }

    searchPaths := []string{
        "./elemta.conf",
        "./config/elemta.conf",
        "../config/elemta.conf",
        os.ExpandEnv("$HOME/.elemta.conf"),
        "/etc/elemta/elemta.conf",
    }

    for _, path := range searchPaths {
        fmt.Printf("Checking for config at: %s\n", path)
        if _, err := os.Stat(path); err == nil {
            fmt.Printf("Found config at: %s\n", path)
            return path, nil
        }
    }

    fmt.Println("No config file found, using defaults")
    return "", fmt.Errorf("no config file found in search paths")
}

func LoadConfig(configPath string) (*Config, error) {
    path, err := findConfigFile(configPath)
    if err != nil {
        return DefaultConfig(), nil
    }

    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var config Config
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }

    if config.Hostname == "" {
        hostname, err := os.Hostname()
        if err == nil {
            config.Hostname = hostname
        } else {
            config.Hostname = "localhost.localdomain"
        }
    }

    if config.ListenAddr == "" {
        config.ListenAddr = ":25"
    }
    if config.QueueDir == "" {
        config.QueueDir = "./queue"
    }
    if config.MaxSize == 0 {
        config.MaxSize = 25 * 1024 * 1024
    }
    if config.MaxWorkers == 0 {
        config.MaxWorkers = 10
    }
    if config.MaxRetries == 0 {
        config.MaxRetries = 10
    }
    if config.MaxQueueTime == 0 {
        config.MaxQueueTime = 172800
    }
    if len(config.RetrySchedule) == 0 {
        config.RetrySchedule = []int{60, 300, 900, 3600, 10800, 21600, 43200}
    }

    if err := os.MkdirAll(config.QueueDir, 0755); err != nil {
        return nil, err
    }

    return &config, nil
}

func DefaultConfig() *Config {
    hostname, err := os.Hostname()
    if err != nil {
        hostname = "localhost.localdomain"
    }

    return &Config{
        ListenAddr:    ":25",
        QueueDir:      "./queue",
        MaxSize:       25 * 1024 * 1024,
        DevMode:       false,
        AllowedRelays: []string{},
        Hostname:      hostname,
        MaxWorkers:    10,
        MaxRetries:    10,
        MaxQueueTime:  172800,
        RetrySchedule: []int{60, 300, 900, 3600, 10800, 21600, 43200},
    }
}
