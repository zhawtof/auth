package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/sethvargo/go-password/password"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// MagicLinkParams holds the parameters for a magic link request
type MagicLinkParams struct {
	Email               string                 `json:"email"`
	FlowType            string                 `json:"flow_type"`
	Data                map[string]interface{} `json:"data"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
}

func (p *MagicLinkParams) Validate() error {
	if p.Email == "" {
		return unprocessableEntityError("Password recovery requires an email")
	}
	var err error
	p.Email, err = validateEmail(p.Email)
	if err != nil {
		return err
	}
	if p.FlowType != models.ImplicitFlow.String() && p.FlowType != models.PKCEFlow.String() {
		return badRequestError(InvalidFlowTypeErrorMessage)
	}

	return nil
}

// MagicLink sends a recovery email
func (a *API) MagicLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	if !config.External.Email.Enabled {
		return badRequestError("Email logins are disabled")
	}

	params := &MagicLinkParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}
	if params.FlowType == "" {
		params.FlowType = models.ImplicitFlow.String()
	}
	if err := params.Validate(); err != nil {
		return err
	}

	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}
	var isNewUser bool
	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(db, params.Email, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			isNewUser = true
		} else {
			return internalServerError("Database error finding user").WithInternalError(err)
		}
	}
	if user != nil {
		isNewUser = !user.IsConfirmed()
	}
	if isNewUser {
		// User either doesn't exist or hasn't completed the signup process.
		// Sign them up with temporary password.
		password, err := password.Generate(64, 10, 0, false, true)
		if err != nil {
			internalServerError("error creating user").WithInternalError(err)
		}

		signUpParams := &SignupParams{
			Email:               params.Email,
			Password:            password,
			Data:                params.Data,
			FlowType:            params.FlowType,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
		}
		newBodyContent, err := json.Marshal(signUpParams)
		if err != nil {
			return badRequestError("Could not parse metadata: %v", err)
		}
		r.Body = io.NopCloser(strings.NewReader(string(newBodyContent)))
		r.ContentLength = int64(len(string(newBodyContent)))

		fakeResponse := &responseStub{}
		if config.Mailer.Autoconfirm {
			// signups are autoconfirmed, send magic link after signup
			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}
			newBodyContent := &SignupParams{
				Email:               params.Email,
				Data:                params.Data,
				FlowType:            params.FlowType,
				CodeChallenge:       params.CodeChallenge,
				CodeChallengeMethod: params.CodeChallengeMethod,
			}
			metadata, err := json.Marshal(newBodyContent)
			if err != nil {
				return badRequestError("Could not parse metadata: %v", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(metadata))
			return a.MagicLink(w, r)
		}
		// otherwise confirmation email already contains 'magic link'
		if err := a.Signup(fakeResponse, r); err != nil {
			return err
		}

		return sendJSON(w, http.StatusOK, make(map[string]string))
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
			return terr
		}
		flowStateID := ""
		if params.FlowType == models.PKCEFlow.String() {
			codeChallengeMethod, err := models.ParseCodeChallengeMethod(params.CodeChallengeMethod)
			if err != nil {
				return err
			}
			providerType := "magiclink"
			flowState, err := models.NewFlowState(providerType, params.CodeChallenge, codeChallengeMethod)
			if err != nil {
				return err
			}
			flowState.UserID = &(user.ID)
			if err := tx.Create(flowState); err != nil {
				return err
			}
			flowStateID = flowState.ID.String()
		}

		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		// Check the flow type here
		return a.sendMagicLink(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength, flowStateID)
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError("Error sending magic link").WithInternalError(err)
	}
	return sendJSON(w, http.StatusOK, make(map[string]string))
}

// responseStub only implement http responsewriter for ignoring
// incoming data from methods where it passed
type responseStub struct {
}

func (rw *responseStub) Header() http.Header {
	return http.Header{}
}

func (rw *responseStub) Write(data []byte) (int, error) {
	return 1, nil
}

func (rw *responseStub) WriteHeader(statusCode int) {
}
