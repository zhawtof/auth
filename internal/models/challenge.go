package models

import (
	"database/sql"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"

	"time"
)

type Challenge struct {
	ID         uuid.UUID  `json:"challenge_id" db:"id"`
	FactorID   uuid.UUID  `json:"factor_id" db:"factor_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	IPAddress  string     `json:"ip_address" db:"ip_address"`
	Factor     *Factor    `json:"factor,omitempty" belongs_to:"factor"`
	// TODO: Change these into enum maybe
	ChallengeType     string `json:"challenge_type"`
	WebauthnChallenge string `json:"webauthn_challenge"`
	UserVerification  string `json:"user_verification"`
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
}

func NewChallenge(factor *Factor, ipAddress string) *Challenge {
	id := uuid.Must(uuid.NewV4())

	challenge := &Challenge{
		ID:        id,
		FactorID:  factor.ID,
		IPAddress: ipAddress,
	}
	return challenge
}

func FindChallengeByID(conn *storage.Connection, challengeID uuid.UUID) (*Challenge, error) {
	var challenge Challenge
	err := conn.Find(&challenge, challengeID)
	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, ChallengeNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// Update the verification timestamp
func (c *Challenge) Verify(tx *storage.Connection) error {
	now := time.Now()
	c.VerifiedAt = &now
	return tx.UpdateOnly(c, "verified_at")
}

func (c *Challenge) HasExpired(expiryDuration float64) bool {
	return time.Now().After(c.GetExpiryTime(expiryDuration))
}

func (c *Challenge) GetExpiryTime(expiryDuration float64) time.Time {
	return c.CreatedAt.Add(time.Second * time.Duration(expiryDuration))
}

// Change so it convert To
// func (c *Challenge) FromWebauthnRegistrationSession(factorID uuid.UUID, ipAddress string, session webauthn.SessionData) *c {

// }

func (c *Challenge) ToWebauthnRegistrationSession(factorID uuid.UUID, ipAddress string, session webauthn.SessionData) *webauthn.SessionData {
	return nil
	// id := uuid.Must(uuid.NewV4())
	// return &Challenge {
	// 	ID: id,
	// 	FactorID: factorID,
	// 	IPAddress: ipAddress,
	// 	// TODO: Have the user sepcify this and add as param to fn
	// 	// ChallengeType: "webauthn_registration",
	// 	// WebauthnChallenge: "challenge_value",

	// }

}

type WebauthnSession struct {
	*webauthn.SessionData
}

func (ws *WebauthnSession) ToChallenge(factorID uuid.UUID, ipAddress string) *Challenge {
	id := uuid.Must(uuid.NewV4())
	return &Challenge{
		ID:        id,
		FactorID:  factorID,
		IPAddress: ipAddress,
		// TODO: Have the user specify this and add as param to fn
		ChallengeType:     "webauthn_registration",
		UserVerification:  "preferred",
		WebauthnChallenge: ws.Challenge,
	}

}
