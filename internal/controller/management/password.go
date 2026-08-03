package management

import (
	"net/http"

	"flux.local/flux/internal/controller/iam"
)

func (s *Server) handleChangePassword(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	session := sessionFromContext(request.Context())
	if !iam.VerifyPassword(session.Account.PasswordHash, input.CurrentPassword) {
		s.auditSession(request.Context(), request, session, "auth.password.change", "account", session.Account.ID, "denied", nil)
		writeError(writer, http.StatusUnauthorized, "invalid_credentials", "current password is invalid")
		return
	}
	passwordHash, err := iam.HashPassword(input.NewPassword)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	if _, err := s.repository.ReplaceAccountPassword(request.Context(), session.Account.ID, passwordHash, session.Account.ResourceVersion); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.clearSessionCookies(writer)
	s.auditSession(request.Context(), request, session, "auth.password.change", "account", session.Account.ID, "success", nil)
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetTenantPassword(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	account, err := s.repository.TenantAccountByTenantID(request.Context(), request.PathValue("tenantID"))
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	passwordHash, err := iam.HashPassword(input.Password)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	if _, err := s.repository.ReplaceAccountPassword(request.Context(), account.ID, passwordHash, account.ResourceVersion); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "tenant.password.reset", "tenant", request.PathValue("tenantID"), "success", nil)
	writer.WriteHeader(http.StatusNoContent)
}
