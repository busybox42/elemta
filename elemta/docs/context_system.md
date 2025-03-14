# Context System and XDEBUG Command

## Context System

The context system in ElemTA is a key-value store that allows you to store and retrieve data associated with an SMTP session. It is similar to the context system in Momentum and can be used to store metadata about the session, such as authentication status, spam scores, and other information.

### Features

- Store and retrieve values of different types (string, int, float, bool)
- Set expiration times for values
- Clear the context
- Dump the context for debugging

### Usage in Code

```go
// Get the session context
ctx := session.Context

// Set a value
ctx.Set("key", "value")

// Set a value with expiration
ctx.SetWithExpiration("key", "value", 5*time.Minute)

// Get a value
value, ok := ctx.Get("key")

// Get a value as a specific type
strValue, ok := ctx.GetString("key")
intValue, ok := ctx.GetInt("key")
floatValue, ok := ctx.GetFloat("key")
boolValue, ok := ctx.GetBool("key")

// Delete a value
ctx.Delete("key")

// Clear the context
ctx.Clear()

// Get all keys
keys := ctx.Keys()

// Get the number of values
count := ctx.Count()

// Dump the context
dump := ctx.Dump()
```

### Usage in Rules

In rule scripts, you can access the context through the `ctx` object:

```lua
-- Set a value
ctx:SetMetadata("key", "value")

-- Get a value
local value = ctx:GetMetadata("key")

-- Delete a value
ctx:DeleteMetadata("key")
```

## XDEBUG Command

The XDEBUG command is a custom SMTP command that allows you to debug the SMTP session. It provides information about the session, including the context.

### Usage

```
XDEBUG
```

This will dump all debug information, including the session and context.

```
XDEBUG CONTEXT
```

This will dump only the context.

```
XDEBUG CONTEXT GET <key>
```

This will get a specific value from the context.

```
XDEBUG CONTEXT SET <key> <value>
```

This will set a specific value in the context.

```
XDEBUG CONTEXT DELETE <key>
```

This will delete a specific value from the context.

```
XDEBUG CONTEXT CLEAR
```

This will clear the context.

```
XDEBUG SESSION
```

This will dump only the session information.

```
XDEBUG HELP
```

This will show help information for the XDEBUG command.

### Example

```
EHLO example.com
250-mercury.example.com
250-SIZE 52428800
250-8BITMIME
250-PIPELINING
250-ENHANCEDSTATUSCODES
250-STARTTLS
250-AUTH PLAIN LOGIN
250 HELP

XDEBUG CONTEXT SET spam_score 0.95
250 Set spam_score = 0.95

XDEBUG CONTEXT GET spam_score
250 spam_score = 0.95

XDEBUG CONTEXT
250-Context dump:
250 spam_score = 0.95 (set at 2023-06-01T12:34:56Z, expires never)

XDEBUG
250-Debug information:
250-Session ID: 1
250-State: HELO/EHLO
250-Client IP: 192.168.1.1
250-Client Name: 
250-Hostname: example.com
250-Mail From: 
250-Rcpt To: []
250-Secure: false
250-Authenticated: false
250-TLS Enabled: false
250-Start Time: 2023-06-01T12:34:56Z
250-Last Activity: 2023-06-01T12:34:56Z
250-Extensions: map[8BITMIME:true AUTH:true ENHANCEDSTATUSCODES:true HELP:true PIPELINING:true SIZE:true STARTTLS:true]
250-Context:
250 spam_score = 0.95 (set at 2023-06-01T12:34:56Z, expires never)
``` 