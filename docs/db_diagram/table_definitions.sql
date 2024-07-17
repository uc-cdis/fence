
-- This is a non-comprehensive list of table definitions for for
-- corresponding ORMs

CREATE TABLE public.ga4gh_passport_cache (
    passport_hash character varying(64) NOT NULL,
    expires_at bigint NOT NULL,
    user_ids character varying(255)[] NOT NULL
);

CREATE TABLE public.ga4gh_visa_v1 (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    ga4gh_visa text NOT NULL,
    source character varying NOT NULL,
    type character varying NOT NULL,
    asserted bigint NOT NULL,
    expires bigint NOT NULL
);

CREATE TABLE public.gcp_assume_role_cache (
    gcp_proxy_group_id character varying NOT NULL,
    expires_at integer,
    gcp_private_key character varying,
    gcp_key_db_entry character varying
);

CREATE TABLE public.google_service_account (
    id integer NOT NULL,
    google_unique_id character varying NOT NULL,
    client_id character varying(40),
    user_id integer,
    google_project_id character varying NOT NULL,
    email character varying NOT NULL
);

CREATE TABLE public.google_service_account_key (
    id integer NOT NULL,
    key_id character varying NOT NULL,
    service_account_id integer,
    expires bigint,
    private_key character varying
);

CREATE TABLE iss_sub_pair_to_user (
    iss VARCHAR,
    sub VARCHAR,
    "fk_to_User" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
    extra_info JSONB DEFAULT '{}',
    PRIMARY KEY (iss, sub)
);
