# Custom Policy Plugin

This document describes how to create and use custom policy plugins with Elemta SMTP server.

## Overview

Policy plugins allow you to implement custom rules for accepting or rejecting email messages at different stages of the SMTP transaction. They can be used to:

- Implement rate limiting
- Control relaying
- Filter based on sender or recipient domains
- Implement IP reputation checks
- Apply content-based policies

## Example Policy Plugin

An example policy plugin is provided in `examples/plugins/example_policy.go`. This plugin demonstrates several common policy features:

1. **Rate limiting**: Limits the number of messages per minute from a single IP address
2. **Sender domain filtering**: Allows only specific sender domains
3. **Recipient domain filtering**: Blocks specific recipient domains
4. **Relay control**: Controls which domains can be relayed through the server
5. **IP reputation**: Rejects connections from IPs with poor reputation scores

### Plugin Structure

The example policy plugin implements several hook methods that are called at different stages of the SMTP transaction:

- `OnConnect`: Called when a client connects to the server
- `OnMailFrom`: Called when a client issues a MAIL FROM command
- `OnRcptTo`: Called when a client issues a RCPT TO command
- `OnData`: Called when a client sends message data

Each hook method can return one of the following actions:

- `ActionContinue`: Continue processing the message
- `ActionReject`: Reject the message with an SMTP error
- `ActionDiscard`: Silently discard the message
- `ActionQuarantine`: Quarantine the message for further analysis

### Configuration

The example policy plugin uses the following configuration structure:

```yaml
plugins:
  - name: policy
    enabled: true
    config:
      max_messages_per_minute: 60
      max_recipients_per_message: 50
      allowed_sender_domains:
        - example.com
        - trusted.org
      blocked_recipient_domains:
        - blocked.com
        - spam.org
      allowed_relay_domains:
        - example.com
        - trusted.org
      block_bad_reputation: true
      min_reputation_score: 50
```

## Creating Your Own Policy Plugin

To create your own policy plugin, follow these steps:

1. Create a new Go file for your plugin
2. Import the necessary packages:
   ```go
   import (
       "github.com/busybox42/elemta/internal/plugin"
       "github.com/busybox42/elemta/internal/smtp"
   )
   ```
3. Define your plugin structure:
   ```go
   type MyPolicyPlugin struct {
       plugin.BasePlugin
       // Add your custom fields here
   }
   ```
4. Implement the necessary hook methods:
   ```go
   func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
       // Your code here
   }
   
   func (p *MyPolicyPlugin) OnMailFrom(ctx *plugin.Context) (*plugin.Result, error) {
       // Your code here
   }
   
   func (p *MyPolicyPlugin) OnRcptTo(ctx *plugin.Context) (*plugin.Result, error) {
       // Your code here
   }
   
   func (p *MyPolicyPlugin) OnData(ctx *plugin.Context) (*plugin.Result, error) {
       // Your code here
   }
   ```
5. Create and export an instance of your plugin:
   ```go
   var PolicyPlugin = &MyPolicyPlugin{
       // Initialize your plugin
   }
   ```

## Building and Installing

To build and install your policy plugin:

1. Place your plugin code in a Go file
2. Build it as a shared library:
   ```bash
   go build -buildmode=plugin -o mypolicy.so mypolicy.go
   ```
3. Copy the shared library to the Elemta plugins directory:
   ```bash
   cp mypolicy.so /etc/elemta/plugins/
   ```
4. Configure Elemta to use your plugin in `elemta.yaml`:
   ```yaml
   plugins:
     - name: mypolicy
       path: /etc/elemta/plugins/mypolicy.so
       enabled: true
       config:
         # Your plugin configuration here
   ```
5. Restart Elemta:
   ```bash
   systemctl restart elemta
   ```

## Best Practices

When creating policy plugins, follow these best practices:

1. **Performance**: Keep your policy checks efficient, especially in the `OnConnect` and `OnData` hooks
2. **Error Handling**: Always handle errors gracefully and provide meaningful error messages
3. **Logging**: Log important events and decisions for troubleshooting
4. **Configuration**: Make your plugin configurable to adapt to different environments
5. **Testing**: Test your plugin thoroughly with different inputs and edge cases

## Metrics

Consider exposing metrics from your policy plugin to monitor its behavior:

```go
// Example of exposing metrics
func (p *MyPolicyPlugin) Init() error {
    // Register metrics
    metrics.RegisterCounter("policy_rejected_connections_total", "Total number of connections rejected by policy")
    metrics.RegisterCounter("policy_rejected_senders_total", "Total number of senders rejected by policy")
    metrics.RegisterCounter("policy_rejected_recipients_total", "Total number of recipients rejected by policy")
    metrics.RegisterCounter("policy_rejected_messages_total", "Total number of messages rejected by policy")
    
    return nil
}

// Increment metrics in your hook methods
func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
    // Your policy logic
    if shouldReject {
        metrics.IncrementCounter("policy_rejected_connections_total")
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Connection rejected by policy",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Connection accepted",
    }, nil
}
```

## Examples by SMTP Transaction Phase

### 1. Connection Phase (OnConnect)

This phase occurs when a client first connects to the SMTP server.

#### IP Blocklist

```go
func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    remoteIP := session.RemoteAddr.(*net.TCPAddr).IP.String()
    
    // Check if IP is in blocklist
    if p.isIPBlocked(remoteIP) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Your IP address is blocked",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Connection accepted",
    }, nil
}
```

#### Connection Rate Limiting

```go
func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    remoteIP := session.RemoteAddr.(*net.TCPAddr).IP.String()
    
    // Check connection rate
    if !p.checkConnectionRate(remoteIP) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Too many connections from your IP, please try again later",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Connection accepted",
    }, nil
}

func (p *MyPolicyPlugin) checkConnectionRate(ip string) bool {
    now := time.Now()
    key := "conn:" + ip
    
    // Get current count
    count, exists := p.rateLimits[key]
    if !exists {
        p.rateLimits[key] = 1
        p.lastReset[key] = now
        return true
    }
    
    // Reset counter if window has passed
    lastReset := p.lastReset[key]
    if now.Sub(lastReset) > time.Minute {
        p.rateLimits[key] = 1
        p.lastReset[key] = now
        return true
    }
    
    // Check if limit exceeded
    if count >= p.config.MaxConnectionsPerMinute {
        return false
    }
    
    // Increment counter
    p.rateLimits[key]++
    return true
}
```

#### Time-Based Access Control

```go
func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
    // Get current time
    now := time.Now()
    hour := now.Hour()
    
    // Only allow connections during business hours (9 AM to 5 PM)
    if hour < 9 || hour >= 17 {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Server is only available during business hours (9 AM to 5 PM)",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Connection accepted",
    }, nil
}
```

### 2. Authentication Phase (OnAuth)

This phase occurs when a client attempts to authenticate.

#### Failed Authentication Rate Limiting

```go
func (p *MyPolicyPlugin) OnAuth(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    remoteIP := session.RemoteAddr.(*net.TCPAddr).IP.String()
    username := ctx.Auth.Username
    
    // Check if this IP has too many failed auth attempts
    if p.tooManyFailedAttempts(remoteIP) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Too many failed authentication attempts, please try again later",
        }, nil
    }
    
    // If authentication fails, record it
    if !ctx.Auth.Authenticated {
        p.recordFailedAttempt(remoteIP, username)
    } else {
        // Reset failed attempts on successful auth
        p.resetFailedAttempts(remoteIP, username)
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Authentication processed",
    }, nil
}
```

#### Restricted Authentication Hours

```go
func (p *MyPolicyPlugin) OnAuth(ctx *plugin.Context) (*plugin.Result, error) {
    username := ctx.Auth.Username
    
    // Check if user is allowed to authenticate at this time
    if !p.isAuthTimeAllowed(username) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Authentication not allowed at this time for this user",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Authentication allowed",
    }, nil
}

func (p *MyPolicyPlugin) isAuthTimeAllowed(username string) bool {
    now := time.Now()
    hour := now.Hour()
    
    // Check user-specific restrictions
    if restrictions, exists := p.userRestrictions[username]; exists {
        return hour >= restrictions.StartHour && hour < restrictions.EndHour
    }
    
    // Default to allowed if no specific restrictions
    return true
}
```

### 3. MAIL FROM Phase (OnMailFrom)

This phase occurs when a client issues a MAIL FROM command.

#### Sender Domain Filtering

```go
func (p *MyPolicyPlugin) OnMailFrom(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    envelope := session.Envelope
    
    // Extract domain from sender
    parts := strings.Split(envelope.MailFrom.Address, "@")
    if len(parts) != 2 {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Invalid sender address format",
        }, nil
    }
    
    senderDomain := strings.ToLower(parts[1])
    
    // Check if sender domain is allowed
    if !p.isAllowedSenderDomain(senderDomain) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: fmt.Sprintf("Sender domain %s is not allowed", senderDomain),
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Sender accepted",
    }, nil
}
```

#### Sender Address Validation

```go
func (p *MyPolicyPlugin) OnMailFrom(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    envelope := session.Envelope
    
    // Check for null sender (bounce message)
    if envelope.MailFrom.Address == "" {
        // Special handling for bounce messages
        if !session.IsAuthenticated {
            return &plugin.Result{
                Action:  plugin.ActionReject,
                Message: "Unauthenticated bounce messages not accepted",
            }, nil
        }
    }
    
    // Validate sender email format
    if !p.isValidEmailFormat(envelope.MailFrom.Address) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Invalid sender email format",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Sender accepted",
    }, nil
}

func (p *MyPolicyPlugin) isValidEmailFormat(email string) bool {
    // Simple regex for email validation
    // In a real implementation, you would use a more robust validation
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    return emailRegex.MatchString(email)
}
```

### 4. RCPT TO Phase (OnRcptTo)

This phase occurs when a client issues a RCPT TO command.

#### Recipient Domain Filtering

```go
func (p *MyPolicyPlugin) OnRcptTo(ctx *plugin.Context) (*plugin.Result, error) {
    rcptTo := ctx.RcptTo
    
    // Extract domain from recipient
    parts := strings.Split(rcptTo.Address, "@")
    if len(parts) != 2 {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Invalid recipient address format",
        }, nil
    }
    
    recipientDomain := strings.ToLower(parts[1])
    
    // Check if recipient domain is blocked
    if p.isBlockedRecipientDomain(recipientDomain) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: fmt.Sprintf("Recipient domain %s is blocked", recipientDomain),
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Recipient accepted",
    }, nil
}
```

#### Relay Control

```go
func (p *MyPolicyPlugin) OnRcptTo(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    rcptTo := ctx.RcptTo
    
    // Extract domain from recipient
    parts := strings.Split(rcptTo.Address, "@")
    if len(parts) != 2 {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Invalid recipient address format",
        }, nil
    }
    
    recipientDomain := strings.ToLower(parts[1])
    
    // Check if we're allowed to relay to this domain
    if !session.IsAuthenticated {
        // For unauthenticated sessions, check if the domain is in our allowed relay domains
        if !p.isAllowedRelayDomain(recipientDomain) {
            return &plugin.Result{
                Action:  plugin.ActionReject,
                Message: "Relay access denied",
            }, nil
        }
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Recipient accepted",
    }, nil
}
```

#### Maximum Recipients Per Message

```go
func (p *MyPolicyPlugin) OnRcptTo(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    envelope := session.Envelope
    
    // Check if we've exceeded the maximum recipients per message
    if len(envelope.RcptTo) >= p.config.MaxRecipientsPerMessage {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: fmt.Sprintf("Maximum recipients per message (%d) exceeded", p.config.MaxRecipientsPerMessage),
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Recipient accepted",
    }, nil
}
```

### 5. DATA Phase (OnData)

This phase occurs when a client sends message data.

#### Content Filtering

```go
func (p *MyPolicyPlugin) OnData(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    reader := session.DataReader
    
    // Read message data
    data, err := io.ReadAll(reader)
    if err != nil {
        return nil, err
    }
    
    // Check for prohibited content
    if p.containsProhibitedContent(data) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Message contains prohibited content",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Message accepted",
    }, nil
}

func (p *MyPolicyPlugin) containsProhibitedContent(data []byte) bool {
    content := string(data)
    
    // Check for prohibited keywords
    prohibitedKeywords := []string{
        "viagra", "cialis", "buy now", "free offer", "limited time",
        "discount", "cheap", "money back", "guarantee", "winner",
        "lottery", "prize", "congratulations", "million dollars",
    }
    
    for _, keyword := range prohibitedKeywords {
        if strings.Contains(strings.ToLower(content), keyword) {
            return true
        }
    }
    
    return false
}
```

#### Message Size Limit

```go
func (p *MyPolicyPlugin) OnData(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    
    // Check message size
    if session.DataSize > p.config.MaxMessageSize {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: fmt.Sprintf("Message size exceeds maximum allowed (%d bytes)", p.config.MaxMessageSize),
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Message accepted",
    }, nil
}
```

#### Attachment Filtering

```go
func (p *MyPolicyPlugin) OnData(ctx *plugin.Context) (*plugin.Result, error) {
    session := ctx.Session
    reader := session.DataReader
    
    // Parse the email message
    msg, err := mail.ReadMessage(reader)
    if err != nil {
        return nil, err
    }
    
    // Check for prohibited attachments
    if p.hasProhibitedAttachments(msg) {
        return &plugin.Result{
            Action:  plugin.ActionReject,
            Message: "Message contains prohibited attachments",
        }, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Message accepted",
    }, nil
}

func (p *MyPolicyPlugin) hasProhibitedAttachments(msg *mail.Message) bool {
    mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
    if err != nil {
        return false
    }
    
    if strings.HasPrefix(mediaType, "multipart/") {
        boundary := params["boundary"]
        if boundary == "" {
            return false
        }
        
        mr := multipart.NewReader(msg.Body, boundary)
        for {
            part, err := mr.NextPart()
            if err == io.EOF {
                break
            }
            if err != nil {
                return false
            }
            
            // Check attachment filename and content type
            filename := part.FileName()
            if filename != "" {
                ext := strings.ToLower(filepath.Ext(filename))
                if p.isProhibitedExtension(ext) {
                    return true
                }
            }
        }
    }
    
    return false
}

func (p *MyPolicyPlugin) isProhibitedExtension(ext string) bool {
    prohibitedExtensions := []string{
        ".exe", ".bat", ".cmd", ".msi", ".js", ".vbs", ".ps1",
        ".jar", ".scr", ".pif", ".reg", ".com", ".hta",
    }
    
    for _, prohibited := range prohibitedExtensions {
        if ext == prohibited {
            return true
        }
    }
    
    return false
}
```

## Combining Multiple Policies

You can combine multiple policies in a single plugin:

```go
func (p *MyPolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
    // IP blocklist check
    if result := p.checkIPBlocklist(ctx); result != nil {
        return result, nil
    }
    
    // Connection rate limiting
    if result := p.checkConnectionRate(ctx); result != nil {
        return result, nil
    }
    
    // Time-based access control
    if result := p.checkTimeBasedAccess(ctx); result != nil {
        return result, nil
    }
    
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Connection accepted",
    }, nil
}
```

## Troubleshooting

If your policy plugin is not working as expected:

1. Check the Elemta logs for error messages
2. Enable debug logging in your plugin
3. Verify that your plugin is being loaded correctly
4. Test your plugin with simple policies first
5. Use the `elemta test-plugin` command to test your plugin in isolation 