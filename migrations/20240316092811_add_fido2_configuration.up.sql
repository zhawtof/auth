do $$ begin
   create table if not exists {{ index .Options "Namespace" }}.webauthn_factor_information(
        id uuid not null,
        factor_id uuid not null,
        public_key jsonb not null,
        aaguid uuid null,
        constraint webauthn_credential_factor_id_fkey foreign key (factor_id) references {{ index .Options "Namespace"}}.mfa_factors(id) on delete cascade
   );
   -- TODO: Add a more informative comment
   comment on table {{ index .Options "Namespace" }}.webauthn_credential is 'auth: stores metadata specific to webauthn credential';
   -- TODO: Add constraint to ensure it can only be non-nullable when it's a webauthn factor
   alter table {{ index.Options "Namespace"}}.mfa_factors add column if not exists webauthn_credential_id null;
   alter table {{ index.Options "Namespace"}}.mfa_challenges add column webauthn_challenge if not exists string null;
   -- TODO: There's one more field, add it here
   alter table {{ index.Options "Namespace"}}.mfa_challenges add column authenticator_selection if not exists jsonb null;
end $$
