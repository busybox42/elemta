package smtp

import (
    "encoding/json"
    "fmt"
    "log/slog"
    "net"
    "net/textproto"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type MessageInfo struct {
    ID        string        `json:"id"`
    From      string        `json:"from"`
    To        []string      `json:"to"`
    Status    MessageStatus `json:"status"`
    CreatedAt time.Time     `json:"created_at"`
    UpdatedAt time.Time     `json:"updated_at"`
}

type DeliveryManager struct {
    config     *Config
    logger     *slog.Logger
    running    bool
    activeMu   sync.Mutex
    activeJobs map[string]bool
}

func NewDeliveryManager(config *Config) *DeliveryManager {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    }))

    return &DeliveryManager{
        config:     config,
        logger:     logger,
        activeJobs: make(map[string]bool),
    }
}

func (dm *DeliveryManager) Start() {
    dm.running = true
    go dm.processQueue()
}

func (dm *DeliveryManager) Stop() {
    dm.running = false
}

func (dm *DeliveryManager) processQueue() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for dm.running {
        <-ticker.C
        
        files, err := os.ReadDir(dm.config.QueueDir)
        if err != nil {
            dm.logger.Error("failed to read queue directory", "error", err)
            continue
        }

        for _, file := range files {
            if filepath.Ext(file.Name()) == ".json" {
                continue
            }

            msgPath := filepath.Join(dm.config.QueueDir, file.Name())
            if err := dm.deliverMessage(msgPath); err != nil {
                dm.logger.Error("delivery failed", 
                    "message_id", file.Name(),
                    "error", err)
            }
        }
    }
}

func (dm *DeliveryManager) deliverMessage(path string) error {
    messageID := filepath.Base(path)

    // Atomic job tracking
    dm.activeMu.Lock()
    if dm.activeJobs[messageID] {
        dm.activeMu.Unlock()
        return nil // Already being processed
    }
    dm.activeJobs[messageID] = true
    dm.activeMu.Unlock()

    defer func() {
        dm.activeMu.Lock()
        delete(dm.activeJobs, messageID)
        dm.activeMu.Unlock()
    }()

    // Read message data
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }

    metaPath := path + ".json"
    info, err := dm.loadMetadata(metaPath)
    if err != nil {
        return err
    }

    // Skip if not in deliverable state
    if info.Status != StatusQueued && info.Status != StatusFailed {
        return nil
    }

    // Update status to delivering
    info.Status = StatusDelivering
    info.UpdatedAt = time.Now()
    if err := dm.saveMetadata(metaPath, info); err != nil {
        return err
    }

    // Attempt delivery
    if err := dm.attemptDelivery(info, data); err != nil {
        info.Status = StatusFailed
        dm.saveMetadata(metaPath, info)
        return err
    }

    // Update final status to delivered
    info.Status = StatusDelivered
    info.UpdatedAt = time.Now()
    if err := dm.saveMetadata(metaPath, info); err != nil {
        return err
    }

    // Cleanup message file after successful delivery
    if err := os.Remove(path); err != nil {
        dm.logger.Error("Failed to remove delivered message file", "message_id", messageID, "error", err)
    } else {
        dm.logger.Info("Message file removed after successful delivery", "message_id", messageID)
    }

    // Cleanup metadata file after successful delivery
    if err := os.Remove(metaPath); err != nil {
        dm.logger.Error("Failed to remove metadata file", "message_id", messageID, "error", err)
    } else {
        dm.logger.Info("Metadata file removed after successful delivery", "message_id", messageID)
    }

    return nil
}

func (dm *DeliveryManager) attemptDelivery(info *MessageInfo, data []byte) error {
    if dm.config.DevMode {
        dm.logger.Info("dev mode: simulating delivery",
            "message_id", info.ID,
            "from", info.From,
            "to", info.To)
        return nil
    }

    var lastError error
    for _, recipient := range info.To {
        if err := dm.deliverToRecipient(recipient, info.From, data); err != nil {
            lastError = err
            dm.logger.Error("recipient delivery failed",
                "message_id", info.ID,
                "recipient", recipient,
                "error", err)
            continue
        }
        dm.logger.Info("recipient delivery successful",
            "message_id", info.ID,
            "recipient", recipient)
    }
    return lastError
}

func (dm *DeliveryManager) deliverToRecipient(recipient, from string, data []byte) error {
    parts := strings.Split(recipient, "@")
    if len(parts) != 2 {
        return fmt.Errorf("invalid recipient address: %s", recipient)
    }
    domain := parts[1]

    // Try the localhost first if it's a local delivery
    if domain == "localhost" || domain == "127.0.0.1" {
        return dm.deliverToHost("localhost", 25, recipient, from, data)
    }

    // Try MX records first
    mxRecords, err := net.LookupMX(domain)
    if err == nil && len(mxRecords) > 0 {
        for _, mx := range mxRecords {
            mxHost := strings.TrimSuffix(mx.Host, ".")
            if err := dm.deliverToHost(mxHost, 25, recipient, from, data); err == nil {
                return nil
            }
        }
    }

    // Fallback to A/AAAA records if no MX records or all MX attempts failed
    dm.logger.Info("no MX records found or all MX attempts failed, trying A/AAAA records", "domain", domain)
    
    // Try A records
    ips, err := net.LookupIP(domain)
    if err != nil {
        return fmt.Errorf("failed to resolve domain %s: %v", domain, err)
    }

    for _, ip := range ips {
        if err := dm.deliverToHost(ip.String(), 25, recipient, from, data); err == nil {
            return nil
        }
    }

    return fmt.Errorf("delivery failed to all possible servers for %s", domain)
}

func (dm *DeliveryManager) deliverToHost(host string, port int, recipient, from string, data []byte) error {
    addr := fmt.Sprintf("%s:%d", host, port)
    dm.logger.Info("attempting delivery", "server", addr, "recipient", recipient)

    // Set timeout for the connection
    dialer := net.Dialer{
        Timeout: 30 * time.Second,
    }

    // Connect to the SMTP server
    conn, err := dialer.Dial("tcp", addr)
    if err != nil {
        return fmt.Errorf("connection failed to %s: %v", addr, err)
    }

    // Create text proto client to read SMTP responses
    textConn := textproto.NewConn(conn)
    defer textConn.Close()

    // Read initial greeting
    code, msg, err := textConn.ReadResponse(220)
    if err != nil {
        dm.logger.Error("server greeting error", 
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("server greeting failed: %v", err)
    }
    dm.logger.Info("server greeting", 
        "server", addr,
        "code", code,
        "message", msg)

    // Send HELO with configured hostname
    id, err := textConn.Cmd("HELO %s", dm.config.Hostname)
    if err != nil {
        return fmt.Errorf("HELO command failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(250)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("HELO error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("HELO failed: %v", err)
    }
    dm.logger.Info("HELO response",
        "server", addr,
        "code", code,
        "message", msg)

    // Send MAIL FROM
    id, err = textConn.Cmd("MAIL FROM:<%s>", from)
    if err != nil {
        return fmt.Errorf("MAIL FROM command failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(250)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("MAIL FROM error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("MAIL FROM failed: %v", err)
    }
    dm.logger.Info("MAIL FROM response",
        "server", addr,
        "code", code,
        "message", msg)

    // Send RCPT TO
    id, err = textConn.Cmd("RCPT TO:<%s>", recipient)
    if err != nil {
        return fmt.Errorf("RCPT TO command failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(250)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("RCPT TO error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("RCPT TO failed: %v", err)
    }
    dm.logger.Info("RCPT TO response",
        "server", addr,
        "code", code,
        "message", msg)

    // Send DATA
    id, err = textConn.Cmd("DATA")
    if err != nil {
        return fmt.Errorf("DATA command failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(354)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("DATA initiation error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("DATA initiation failed: %v", err)
    }
    dm.logger.Info("DATA initiation response",
        "server", addr,
        "code", code,
        "message", msg)

    // Send message content
    id, err = textConn.Cmd(string(data) + "\r\n.")
    if err != nil {
        return fmt.Errorf("sending message content failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(250)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("message content error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
        return fmt.Errorf("message content failed: %v", err)
    }
    dm.logger.Info("message content response",
        "server", addr,
        "code", code,
        "message", msg)

    // Send QUIT
    id, err = textConn.Cmd("QUIT")
    if err != nil {
        return fmt.Errorf("QUIT command failed: %v", err)
    }
    textConn.StartResponse(id)
    code, msg, err = textConn.ReadResponse(221)
    textConn.EndResponse(id)
    if err != nil {
        dm.logger.Error("QUIT error",
            "server", addr,
            "code", code,
            "message", msg,
            "error", err)
    } else {
        dm.logger.Info("QUIT response",
            "server", addr,
            "code", code,
            "message", msg)
    }

    dm.logger.Info("delivery successful", "server", addr, "recipient", recipient)
    return nil
}

func (dm *DeliveryManager) loadMetadata(path string) (*MessageInfo, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var info MessageInfo
    if err := json.Unmarshal(data, &info); err != nil {
        return nil, err
    }
    return &info, nil
}

func (dm *DeliveryManager) saveMetadata(path string, info *MessageInfo) error {
    data, err := json.Marshal(info)
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}