package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RBAC errors
var (
	ErrPermissionDenied  = errors.New("permission denied")
	ErrRoleNotFound      = errors.New("role not found")
	ErrInvalidPermission = errors.New("invalid permission")
	ErrUserNotInRole     = errors.New("user not in role")
)

// Permission represents a specific permission
type Permission string

// System permissions
const (
	// SMTP permissions
	PermissionSMTPAuth  Permission = "smtp:auth"
	PermissionSMTPSend  Permission = "smtp:send"
	PermissionSMTPRelay Permission = "smtp:relay"

	// Queue permissions
	PermissionQueueView   Permission = "queue:view"
	PermissionQueueManage Permission = "queue:manage"
	PermissionQueueDelete Permission = "queue:delete"
	PermissionQueueFlush  Permission = "queue:flush"

	// User management permissions
	PermissionUserView   Permission = "user:view"
	PermissionUserCreate Permission = "user:create"
	PermissionUserUpdate Permission = "user:update"
	PermissionUserDelete Permission = "user:delete"

	// System administration permissions
	PermissionSystemView   Permission = "system:view"
	PermissionSystemAdmin  Permission = "system:admin"
	PermissionSystemConfig Permission = "system:config"

	// API permissions
	PermissionAPIRead  Permission = "api:read"
	PermissionAPIWrite Permission = "api:write"
	PermissionAPIAdmin Permission = "api:admin"
)

// Role represents a collection of permissions
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	IsSystem    bool         `json:"is_system"` // System roles cannot be deleted
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// RBAC manages role-based access control
type RBAC struct {
	auth  *Auth
	roles map[string]*Role
	mu    sync.RWMutex
}

// NewRBAC creates a new RBAC instance
func NewRBAC(auth *Auth) *RBAC {
	rbac := &RBAC{
		auth:  auth,
		roles: make(map[string]*Role),
	}

	// Initialize default roles
	rbac.initializeDefaultRoles()

	return rbac
}

// initializeDefaultRoles creates the default system roles
func (r *RBAC) initializeDefaultRoles() {
	now := time.Now()

	// Administrator role - full access
	r.roles["admin"] = &Role{
		Name:        "admin",
		Description: "System Administrator - Full Access",
		Permissions: []Permission{
			PermissionSMTPAuth, PermissionSMTPSend, PermissionSMTPRelay,
			PermissionQueueView, PermissionQueueManage, PermissionQueueDelete, PermissionQueueFlush,
			PermissionUserView, PermissionUserCreate, PermissionUserUpdate, PermissionUserDelete,
			PermissionSystemView, PermissionSystemAdmin, PermissionSystemConfig,
			PermissionAPIRead, PermissionAPIWrite, PermissionAPIAdmin,
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// User role - basic access
	r.roles["user"] = &Role{
		Name:        "user",
		Description: "Standard User - Basic Access",
		Permissions: []Permission{
			PermissionSMTPAuth, PermissionSMTPSend,
			PermissionQueueView,
			PermissionAPIRead,
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Operator role - queue management
	r.roles["operator"] = &Role{
		Name:        "operator",
		Description: "Mail Operator - Queue Management",
		Permissions: []Permission{
			PermissionSMTPAuth, PermissionSMTPSend, PermissionSMTPRelay,
			PermissionQueueView, PermissionQueueManage, PermissionQueueFlush,
			PermissionAPIRead, PermissionAPIWrite,
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Read-only role - monitoring only
	r.roles["readonly"] = &Role{
		Name:        "readonly",
		Description: "Read-Only Access - Monitoring",
		Permissions: []Permission{
			PermissionQueueView,
			PermissionSystemView,
			PermissionAPIRead,
		},
		IsSystem:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// HasPermission checks if a user has a specific permission
func (r *RBAC) HasPermission(ctx context.Context, username string, permission Permission) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Get user information
	user, err := r.auth.GetUser(ctx, username)
	if err != nil {
		return false, err
	}

	// Check if user is admin (admin bypasses RBAC)
	if user.IsAdmin {
		return true, nil
	}

	// Check permissions through groups/roles
	for _, groupName := range user.Groups {
		role, exists := r.roles[groupName]
		if !exists {
			continue
		}

		// Check if role has the permission
		for _, perm := range role.Permissions {
			if perm == permission {
				return true, nil
			}
		}
	}

	return false, nil
}

// CheckPermission returns an error if the user doesn't have the permission
func (r *RBAC) CheckPermission(ctx context.Context, username string, permission Permission) error {
	hasPermission, err := r.HasPermission(ctx, username, permission)
	if err != nil {
		return err
	}

	if !hasPermission {
		return fmt.Errorf("%w: user %s lacks permission %s", ErrPermissionDenied, username, permission)
	}

	return nil
}

// Authenticate authenticates a user with username and password
func (r *RBAC) Authenticate(ctx context.Context, username, password string) (bool, error) {
	return r.auth.Authenticate(ctx, username, password)
}

// AddUserToRole adds a user to a role/group
func (r *RBAC) AddUserToRole(ctx context.Context, username, roleName string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check if role exists
	if _, exists := r.roles[roleName]; !exists {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, roleName)
	}

	// Get user
	user, err := r.auth.GetUser(ctx, username)
	if err != nil {
		return err
	}

	// Check if user already has the role
	for _, group := range user.Groups {
		if group == roleName {
			return nil // Already has the role
		}
	}

	// Add role to user's groups
	user.Groups = append(user.Groups, roleName)
	user.UpdatedAt = time.Now().Unix()

	return r.auth.ds.UpdateUser(ctx, user)
}

// RemoveUserFromRole removes a user from a role/group
func (r *RBAC) RemoveUserFromRole(ctx context.Context, username, roleName string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Get user
	user, err := r.auth.GetUser(ctx, username)
	if err != nil {
		return err
	}

	// Remove role from user's groups
	var newGroups []string
	found := false
	for _, group := range user.Groups {
		if group != roleName {
			newGroups = append(newGroups, group)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("%w: %s not in role %s", ErrUserNotInRole, username, roleName)
	}

	user.Groups = newGroups
	user.UpdatedAt = time.Now().Unix()

	return r.auth.ds.UpdateUser(ctx, user)
}

// CreateRole creates a new custom role
func (r *RBAC) CreateRole(name, description string, permissions []Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if role already exists
	if _, exists := r.roles[name]; exists {
		return fmt.Errorf("role %s already exists", name)
	}

	// Validate permissions
	for _, perm := range permissions {
		if !r.isValidPermission(perm) {
			return fmt.Errorf("%w: %s", ErrInvalidPermission, perm)
		}
	}

	// Create role
	now := time.Now()
	r.roles[name] = &Role{
		Name:        name,
		Description: description,
		Permissions: permissions,
		IsSystem:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	return nil
}

// UpdateRole updates an existing role
func (r *RBAC) UpdateRole(name, description string, permissions []Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	role, exists := r.roles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, name)
	}

	// Cannot modify system roles
	if role.IsSystem {
		return fmt.Errorf("cannot modify system role: %s", name)
	}

	// Validate permissions
	for _, perm := range permissions {
		if !r.isValidPermission(perm) {
			return fmt.Errorf("%w: %s", ErrInvalidPermission, perm)
		}
	}

	// Update role
	role.Description = description
	role.Permissions = permissions
	role.UpdatedAt = time.Now()

	return nil
}

// DeleteRole deletes a custom role
func (r *RBAC) DeleteRole(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	role, exists := r.roles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, name)
	}

	// Cannot delete system roles
	if role.IsSystem {
		return fmt.Errorf("cannot delete system role: %s", name)
	}

	delete(r.roles, name)
	return nil
}

// GetRole returns a role by name
func (r *RBAC) GetRole(name string) (*Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role, exists := r.roles[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, name)
	}

	// Return a copy to prevent external modification
	roleCopy := *role
	roleCopy.Permissions = make([]Permission, len(role.Permissions))
	copy(roleCopy.Permissions, role.Permissions)

	return &roleCopy, nil
}

// ListRoles returns all available roles
func (r *RBAC) ListRoles() []*Role {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var roles []*Role
	for _, role := range r.roles {
		// Return a copy to prevent external modification
		roleCopy := *role
		roleCopy.Permissions = make([]Permission, len(role.Permissions))
		copy(roleCopy.Permissions, role.Permissions)
		roles = append(roles, &roleCopy)
	}

	return roles
}

// GetUserPermissions returns all permissions for a user
func (r *RBAC) GetUserPermissions(ctx context.Context, username string) ([]Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, err := r.auth.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	// If user is admin, return all permissions
	if user.IsAdmin {
		return r.getAllPermissions(), nil
	}

	// Collect unique permissions from all user roles
	permissionSet := make(map[Permission]bool)

	for _, groupName := range user.Groups {
		role, exists := r.roles[groupName]
		if !exists {
			continue
		}

		for _, perm := range role.Permissions {
			permissionSet[perm] = true
		}
	}

	// Convert to slice
	var permissions []Permission
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// isValidPermission checks if a permission is valid
func (r *RBAC) isValidPermission(permission Permission) bool {
	validPermissions := []Permission{
		PermissionSMTPAuth, PermissionSMTPSend, PermissionSMTPRelay,
		PermissionQueueView, PermissionQueueManage, PermissionQueueDelete, PermissionQueueFlush,
		PermissionUserView, PermissionUserCreate, PermissionUserUpdate, PermissionUserDelete,
		PermissionSystemView, PermissionSystemAdmin, PermissionSystemConfig,
		PermissionAPIRead, PermissionAPIWrite, PermissionAPIAdmin,
	}

	for _, valid := range validPermissions {
		if permission == valid {
			return true
		}
	}

	return false
}

// getAllPermissions returns all system permissions
func (r *RBAC) getAllPermissions() []Permission {
	return []Permission{
		PermissionSMTPAuth, PermissionSMTPSend, PermissionSMTPRelay,
		PermissionQueueView, PermissionQueueManage, PermissionQueueDelete, PermissionQueueFlush,
		PermissionUserView, PermissionUserCreate, PermissionUserUpdate, PermissionUserDelete,
		PermissionSystemView, PermissionSystemAdmin, PermissionSystemConfig,
		PermissionAPIRead, PermissionAPIWrite, PermissionAPIAdmin,
	}
}

// PermissionString returns a human-readable description of a permission
func PermissionString(permission Permission) string {
	descriptions := map[Permission]string{
		PermissionSMTPAuth:     "SMTP Authentication",
		PermissionSMTPSend:     "SMTP Send Messages",
		PermissionSMTPRelay:    "SMTP Relay Messages",
		PermissionQueueView:    "View Queue Status",
		PermissionQueueManage:  "Manage Queue Messages",
		PermissionQueueDelete:  "Delete Queue Messages",
		PermissionQueueFlush:   "Flush Queues",
		PermissionUserView:     "View Users",
		PermissionUserCreate:   "Create Users",
		PermissionUserUpdate:   "Update Users",
		PermissionUserDelete:   "Delete Users",
		PermissionSystemView:   "View System Status",
		PermissionSystemAdmin:  "System Administration",
		PermissionSystemConfig: "System Configuration",
		PermissionAPIRead:      "API Read Access",
		PermissionAPIWrite:     "API Write Access",
		PermissionAPIAdmin:     "API Administration",
	}

	if desc, exists := descriptions[permission]; exists {
		return desc
	}

	return string(permission)
}
