create table if not exists {{ index .Options "Namespace" }}.webauthn_factor_information(
        id uuid not null,
        factor_id uuid not null,
        public_key jsonb not null,
        aaguid uuid null,
        constraint webauthn_credential_factor_id_fkey foreign key (factor_id) references {{ index .Options "Namespace"}}.mfa_factors(id) on delete cascade
);
