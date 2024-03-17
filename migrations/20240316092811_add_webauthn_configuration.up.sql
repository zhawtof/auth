do $$ begin
    create type challenge_type as enum('totp', 'webauthn_registration', 'webauthn_login');
    create type user_verification as enum('preferred', 'required', 'discouraged');
exception
    when duplicate_object then null;
end $$;

-- TODO: Wrap in do begin block
create table if not exists {{ index .Options "Namespace" }}.webauthn_factor_information(
        id uuid not null,
        factor_id uuid not null,
        public_key jsonb not null,
        aaguid uuid null,
        constraint webauthn_credential_factor_id_fkey foreign key (factor_id) references {{ index .Options "Namespace"}}.mfa_factors(id) on delete cascade
);

-- TODO: Add constraint so that these constraints can only be used when challenge type is webauthn
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists challenge_type challenge_type null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists webauthn_challenge text null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists user_verification user_verification null;



-- Last SessionData field
