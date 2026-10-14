--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14 (Debian 16.14-1.pgdg13+1)
-- Dumped by pg_dump version 16.14 (Debian 16.14-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    seq bigint NOT NULL,
    ts bigint NOT NULL,
    action text NOT NULL,
    resource text NOT NULL,
    outcome text NOT NULL,
    principal text NOT NULL,
    prev_hash text NOT NULL,
    hash text NOT NULL
);


--
-- Name: busbar_schema; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.busbar_schema (
    version bigint NOT NULL
);


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id text NOT NULL,
    key_id text NOT NULL,
    kind text NOT NULL,
    slot smallint NOT NULL,
    public_id text NOT NULL,
    secret text,
    secret_form text NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    expires_at bigint,
    revoked_at bigint,
    revoke_reason text,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT credentials_kind_check CHECK ((kind = 'sigv4'::text)),
    CONSTRAINT credentials_secret_form_check CHECK ((secret_form = ANY (ARRAY['none'::text, 'recoverable'::text, 'digest'::text]))),
    CONSTRAINT credentials_secret_form_matches CHECK (((secret_form = 'none'::text) = (secret IS NULL))),
    CONSTRAINT credentials_slot_check CHECK ((slot = ANY (ARRAY[0, 1])))
);


--
-- Name: denylist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.denylist (
    sub text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    created_at bigint DEFAULT 0 NOT NULL
);


--
-- Name: keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.keys (
    id text NOT NULL,
    generation_hash text NOT NULL,
    name text NOT NULL,
    allowed_pools text,
    enabled boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    key_group text,
    labels text DEFAULT '{}'::text NOT NULL,
    expires_at bigint,
    deleted_at bigint,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT keys_tombstone_disabled CHECK (((deleted_at IS NULL) OR (enabled = false)))
);


--
-- Name: store_revision; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.store_revision (
    only_row boolean DEFAULT true NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT store_revision_only_row_check CHECK (only_row),
    CONSTRAINT store_revision_revision_check CHECK ((revision >= 0))
);


--
-- Name: usage_ledger; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_ledger (
    bucket_id text NOT NULL,
    window_start bigint NOT NULL,
    model text NOT NULL,
    tokens_input bigint DEFAULT 0 NOT NULL,
    tokens_output bigint DEFAULT 0 NOT NULL,
    tokens_cache_read bigint DEFAULT 0 NOT NULL,
    tokens_cache_write bigint DEFAULT 0 NOT NULL
);


--
-- Name: usage_metering; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_metering (
    key_id text NOT NULL,
    bucket bigint NOT NULL,
    model text NOT NULL,
    provider text NOT NULL,
    tokens_input bigint DEFAULT 0 NOT NULL,
    tokens_output bigint DEFAULT 0 NOT NULL,
    tokens_cache_read bigint DEFAULT 0 NOT NULL,
    tokens_cache_write bigint DEFAULT 0 NOT NULL,
    requests bigint DEFAULT 0 NOT NULL,
    billable_requests bigint DEFAULT 0 NOT NULL,
    key_group_at_use text DEFAULT ''::text NOT NULL,
    pricing_version text DEFAULT ''::text NOT NULL
);


--
-- Name: usage_windows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_windows (
    bucket_id text NOT NULL,
    window_start bigint NOT NULL,
    requests bigint DEFAULT 0 NOT NULL,
    billable_requests bigint DEFAULT 0 NOT NULL
);


--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) VALUES (1, 1791956331, 'key.create', 'key:vk_4f0b2b4954ccf1f562928c9c9fb06a13', 'applied', 'admin', '', 'e0ab47ff06b98cc2c7368218bcd3a2759691aa5127192636668e301bc5c45e29');
INSERT INTO public.audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) VALUES (2, 1791956331, 'key.create', 'key:vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 'applied', 'admin', 'e0ab47ff06b98cc2c7368218bcd3a2759691aa5127192636668e301bc5c45e29', '63215802d22049b88489dc320107555acb125673fa81fb3658a21ee7428cc74f');


--
-- Data for Name: busbar_schema; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.busbar_schema (version) VALUES (6);


--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: denylist; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.keys (id, generation_hash, name, allowed_pools, enabled, created_at, key_group, labels, expires_at, deleted_at, revision) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 'binding:vk_4f0b2b4954ccf1f562928c9c9fb06a13:b3a67460cf238124d070a47f6f905882', 'fixture-grouped', NULL, true, 1791956331, 'fixture', '{}', NULL, NULL, 1);
INSERT INTO public.keys (id, generation_hash, name, allowed_pools, enabled, created_at, key_group, labels, expires_at, deleted_at, revision) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 'binding:vk_72f933cc5b48d4eb4b2bda3d1adbb71a:d01f275ec7aa1d3b11f6c4d5c9745fc2', 'fixture-ungrouped', NULL, true, 1791956331, NULL, '{}', NULL, NULL, 2);


--
-- Data for Name: store_revision; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.store_revision (only_row, revision) VALUES (true, 2);


--
-- Data for Name: usage_ledger; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 0, 'm-chat', 22, 14, 0, 0);
INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 0, 'm-cache', 7, 7, 4, 0);
INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 0, 'm-chat', 11, 7, 0, 0);
INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 0, 'm-cache', 7, 7, 4, 0);
INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('group:fixture@day', 1791936000, 'm-chat', 22, 14, 0, 0);
INSERT INTO public.usage_ledger (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) VALUES ('group:fixture@day', 1791936000, 'm-cache', 7, 7, 4, 0);


--
-- Data for Name: usage_metering; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.usage_metering (key_id, bucket, model, provider, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 1791936000, 'm-cache', 'fixture-openai', 7, 7, 4, 0, 1, 1, '', '');
INSERT INTO public.usage_metering (key_id, bucket, model, provider, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 1791936000, 'm-chat', 'fixture-openai', 22, 14, 0, 0, 2, 2, '', '');
INSERT INTO public.usage_metering (key_id, bucket, model, provider, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 1791936000, 'm-cache', 'fixture-openai', 7, 7, 4, 0, 1, 1, '', '');
INSERT INTO public.usage_metering (key_id, bucket, model, provider, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 1791936000, 'm-chat', 'fixture-openai', 11, 7, 0, 0, 1, 1, '', '');


--
-- Data for Name: usage_windows; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.usage_windows (bucket_id, window_start, requests, billable_requests) VALUES ('vk_4f0b2b4954ccf1f562928c9c9fb06a13', 0, 4, 3);
INSERT INTO public.usage_windows (bucket_id, window_start, requests, billable_requests) VALUES ('vk_72f933cc5b48d4eb4b2bda3d1adbb71a', 0, 2, 2);
INSERT INTO public.usage_windows (bucket_id, window_start, requests, billable_requests) VALUES ('group:fixture@day', 1791936000, 4, 3);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (seq);


--
-- Name: busbar_schema busbar_schema_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.busbar_schema
    ADD CONSTRAINT busbar_schema_pkey PRIMARY KEY (version);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: credentials credentials_public_id_uniq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_public_id_uniq UNIQUE (kind, public_id);


--
-- Name: credentials credentials_slot_uniq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_slot_uniq UNIQUE (key_id, kind, slot);


--
-- Name: denylist denylist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.denylist
    ADD CONSTRAINT denylist_pkey PRIMARY KEY (sub);


--
-- Name: keys keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.keys
    ADD CONSTRAINT keys_pkey PRIMARY KEY (id);


--
-- Name: store_revision store_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.store_revision
    ADD CONSTRAINT store_revision_pkey PRIMARY KEY (only_row);


--
-- Name: usage_ledger usage_ledger_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT usage_ledger_pkey PRIMARY KEY (bucket_id, window_start, model);


--
-- Name: usage_metering usage_metering_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_metering
    ADD CONSTRAINT usage_metering_pkey PRIMARY KEY (key_id, bucket, model, provider);


--
-- Name: usage_windows usage_windows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_windows
    ADD CONSTRAINT usage_windows_pkey PRIMARY KEY (bucket_id, window_start);


--
-- Name: idx_credentials_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_key_id ON public.credentials USING btree (key_id);


--
-- Name: idx_credentials_revision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_revision ON public.credentials USING btree (revision);


--
-- Name: idx_keys_revision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_keys_revision ON public.keys USING btree (revision);


--
-- Name: idx_usage_metering_bucket; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_metering_bucket ON public.usage_metering USING btree (bucket);


--
-- Name: credentials credentials_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.keys(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


