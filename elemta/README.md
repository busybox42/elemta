# ElemTA - High-Performance Mail Transfer Agent

ElemTA is a high-performance, fully scriptable Mail Transfer Agent (MTA) written in Go. It provides a modern, secure, and extensible platform for email delivery with built-in support for all major email authentication standards.

## Features

- RFC 5321-compliant SMTP state machine
- High-performance goroutine-per-connection architecture
- Native Go scripting/rule engine with email processing phases
- Built-in support for modern email authentication standards:
  - SPF validation
  - DKIM signing and verification
  - DMARC policy enforcement
  - ARC (Authenticated Received Chain)
- Integration with anti-spam/anti-virus scanners
  - Rspamd
  - SpamAssassin
  - ClamAV
- DNS-based RBL checks
- Lock-free SMTP session pooling
- BPF-based connection rate limiting
- Web interface for monitoring and management (optional)

## Installation

```bash
go install github.com/elemta/elemta/cmd/elemta@latest
```

## Configuration

Configuration is done via a YAML file. See the `config/` directory for examples.

## Usage

```bash
elemta -config /path/to/config.yaml
```

## License

MIT 