package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/bodsink/rpzd/internal/store"
)

// handleUserList renders the user management page.
func (s *Server) handleUserList(c *gin.Context) {
	users, err := s.db.ListUsers(c.Request.Context())
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load users", err)
		return
	}
	c.HTML(http.StatusOK, "users.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "users",
		"Users":      users,
	})
}

// handleUserNew renders the new user form.
func (s *Server) handleUserNew(c *gin.Context) {
	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "users",
		"IsNew":      true,
	})
}

// handleUserCreate processes the new user form submission.
func (s *Server) handleUserCreate(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	role := c.PostForm("role")

	renderErr := func(msg string) {
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"IsNew":     true,
			"FormUser":  gin.H{"Username": username, "Role": role},
			"Error":     msg,
		})
	}

	if username == "" {
		renderErr("Username is required.")
		return
	}
	if len(username) < 3 || len(username) > 64 {
		renderErr("Username must be between 3 and 64 characters.")
		return
	}
	if len(password) < 8 {
		renderErr("Password must be at least 8 characters.")
		return
	}
	if role != "admin" && role != "viewer" {
		renderErr("Role must be 'admin' or 'viewer'.")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to hash password", err)
		return
	}

	if _, err := s.db.CreateUser(c.Request.Context(), username, string(hash), role); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			renderErr("A user with this username already exists.")
			return
		}
		s.renderError(c, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	s.logger.Info("user created", "new_user", username, "role", role, "by", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/users")
}

// handleUserEdit renders the edit user form.
func (s *Server) handleUserEdit(c *gin.Context) {
	target, ok := s.loadUser(c)
	if !ok {
		return
	}
	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "users",
		"FormUser":   target,
		"IsNew":      false,
	})
}

// handleUserUpdate processes the edit user form submission.
// Supports updating role and optionally changing the password.
func (s *Server) handleUserUpdate(c *gin.Context) {
	target, ok := s.loadUser(c)
	if !ok {
		return
	}

	role := c.PostForm("role")
	newPassword := c.PostForm("password")

	renderErr := func(msg string) {
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"FormUser":  target,
			"IsNew":     false,
			"Error":     msg,
		})
	}

	if role != "admin" && role != "viewer" {
		renderErr("Role must be 'admin' or 'viewer'.")
		return
	}

	// Prevent removing admin role from the last admin user
	if target.Role == "admin" && role != "admin" {
		adminCount, _ := s.countAdminUsers(c)
		if adminCount <= 1 {
			renderErr("Cannot remove admin role from the last admin user.")
			return
		}
	}

	// Change password if provided
	if newPassword != "" {
		if len(newPassword) < 8 {
			renderErr("Password must be at least 8 characters.")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
		if err != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to hash password", err)
			return
		}
		if err := s.db.UpdateUserPassword(c.Request.Context(), target.ID, string(hash)); err != nil {
			s.renderError(c, http.StatusInternalServerError, "Failed to update password", err)
			return
		}
	}

	// Update role
	target.Role = role
	if _, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE users SET role=$1 WHERE id=$2`, role, target.ID); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to update user role", err)
		return
	}

	s.logger.Info("user updated", "target_user", target.Username, "role", role, "by", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/users")
}

// handleUserDelete removes a user.
func (s *Server) handleUserDelete(c *gin.Context) {
	target, ok := s.loadUser(c)
	if !ok {
		return
	}

	// Prevent deleting own account
	if target.ID == currentUser(c).ID {
		s.renderError(c, http.StatusBadRequest, "You cannot delete your own account.", nil)
		return
	}

	// Prevent deleting the last admin
	if target.Role == "admin" {
		adminCount, _ := s.countAdminUsers(c)
		if adminCount <= 1 {
			s.renderError(c, http.StatusBadRequest, "Cannot delete the last admin user.", nil)
			return
		}
	}

	if err := s.db.DeleteUser(c.Request.Context(), target.ID); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to delete user", err)
		return
	}
	s.logger.Info("user deleted", "target_user", target.Username, "by", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/users")
}

// handleUserToggle enables or disables a user account.
func (s *Server) handleUserToggle(c *gin.Context) {
	target, ok := s.loadUser(c)
	if !ok {
		return
	}

	// Prevent disabling own account
	if target.ID == currentUser(c).ID {
		s.renderError(c, http.StatusBadRequest, "You cannot disable your own account.", nil)
		return
	}

	newState := !target.Enabled
	if err := s.db.SetUserEnabled(c.Request.Context(), target.ID, newState); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to toggle user", err)
		return
	}
	s.logger.Info("user toggled", "target_user", target.Username, "enabled", newState, "by", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/users")
}

// loadUser fetches a user by the :id URL parameter.
func (s *Server) loadUser(c *gin.Context) (*store.User, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderError(c, http.StatusBadRequest, "Invalid user ID", nil)
		return nil, false
	}
	user, err := s.db.GetUserByID(c.Request.Context(), id)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load user", err)
		return nil, false
	}
	if user == nil {
		s.renderError(c, http.StatusNotFound, "User not found", nil)
		return nil, false
	}
	return user, true
}

// handleProfilePage renders the change-password form for the currently logged-in user.
func (s *Server) handleProfilePage(c *gin.Context) {
	c.HTML(http.StatusOK, "profile.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "profile",
	})
}

// handleProfileSave processes the change-password form.
func (s *Server) handleProfileSave(c *gin.Context) {
	me := currentUser(c)

	renderErr := func(msg string) {
		c.HTML(http.StatusBadRequest, "profile.html", gin.H{
			"User":       me,
			"CSRFToken":  csrfToken(c),
			"ActivePage": "profile",
			"FormError":  msg,
		})
	}

	current := c.PostForm("current_password")
	newPwd := c.PostForm("new_password")
	confirm := c.PostForm("confirm_password")

	if current == "" || newPwd == "" || confirm == "" {
		renderErr("All fields are required.")
		return
	}
	if len(newPwd) < 8 {
		renderErr("New password must be at least 8 characters.")
		return
	}
	if newPwd != confirm {
		renderErr("New password and confirmation do not match.")
		return
	}

	// Verify current password
	user, err := s.db.GetUserByID(c.Request.Context(), me.ID)
	if err != nil || user == nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load user", err)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)); err != nil {
		renderErr("Current password is incorrect.")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPwd), 12)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to hash password", err)
		return
	}
	if err := s.db.UpdateUserPassword(c.Request.Context(), me.ID, string(hash)); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to update password", err)
		return
	}

	s.logger.Info("password changed", "user", me.Username)
	c.Redirect(http.StatusFound, "/?success=Password+updated+successfully")
}

// countAdminUsers returns the number of admin users.
func (s *Server) countAdminUsers(c *gin.Context) (int, error) {
	var count int
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=TRUE`,
	).Scan(&count)
	return count, err
}
