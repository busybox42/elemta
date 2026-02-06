// internal/smtp/dsn.go
package smtp

// DSNReturnType represents the RET parameter value for DSN (RFC 3461 Section 4.3)
type DSNReturnType string

const (
	DSNReturnFull    DSNReturnType = "FULL"
	DSNReturnHeaders DSNReturnType = "HDRS"
)

// DSNNotifyType represents individual NOTIFY condition values (RFC 3461 Section 4.1)
type DSNNotifyType string

const (
	DSNNotifyNever   DSNNotifyType = "NEVER"
	DSNNotifySuccess DSNNotifyType = "SUCCESS"
	DSNNotifyFailure DSNNotifyType = "FAILURE"
	DSNNotifyDelay   DSNNotifyType = "DELAY"
)

// DSNParams holds envelope-level DSN parameters from MAIL FROM
type DSNParams struct {
	Return DSNReturnType
	EnvID  string
}

// DSNRecipientParams holds per-recipient DSN parameters from RCPT TO
type DSNRecipientParams struct {
	Notify []DSNNotifyType
	ORCPT  string
}
