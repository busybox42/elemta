package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    
    "github.com/busybox42/elemta/internal/smtp"
)

func main() {
    config, err := smtp.LoadConfig("")  // Change this line
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }
    
    // Initialize delivery manager
    deliveryManager := smtp.NewDeliveryManager(config)
    deliveryManager.Start()
    defer deliveryManager.Stop()

    // Set up signal handling
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    listener, err := net.Listen("tcp", config.ListenAddr)
    if err != nil {
        log.Fatalf("Failed to create listener: %v", err)
    }
    defer listener.Close()

    log.Printf("Elemta MTA starting on %s", config.ListenAddr)
    
    // Handle connections in a goroutine
    go func() {
        for {
            conn, err := listener.Accept()
            if err != nil {
                log.Printf("Failed to accept connection: %v", err)
                continue
            }
            go handleConnection(conn, config)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")
}

func handleConnection(conn net.Conn, config *smtp.Config) {
    defer conn.Close()
    session := smtp.NewSession(conn, config)
    if err := session.Handle(); err != nil {
        log.Printf("Session error: %v", err)
    }
}