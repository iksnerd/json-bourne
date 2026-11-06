-- v1: generic evidence model. Additive migrations only; never edit once released.

-- One row per saved run. Events and findings carry the run id; there is no
-- foreign key on purpose, because DuckDB would then refuse the delete-and-reinsert
-- that makes a re-save atomic.
CREATE TABLE runs (
    run_id      VARCHAR     NOT NULL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE events (
    run_id      VARCHAR     NOT NULL,
    seq         BIGINT      NOT NULL, -- position within the run, keeps source order
    ts          TIMESTAMPTZ NOT NULL,
    source      VARCHAR     NOT NULL,
    kind        VARCHAR     NOT NULL,
    fields      JSON,                 -- source-specific attributes
    raw         BLOB,                 -- the original document, as received
    doc_sha256  VARCHAR     NOT NULL  -- of raw, or of the normalised event when raw is empty
);

CREATE TABLE findings (
    run_id         VARCHAR     NOT NULL,
    seq            BIGINT      NOT NULL,
    detector       VARCHAR     NOT NULL,
    tag            VARCHAR     NOT NULL, -- stable condition key; dedupe on this
    severity       INTEGER     NOT NULL,
    window_from    TIMESTAMPTZ,
    window_to      TIMESTAMPTZ,
    baseline_from  TIMESTAMPTZ,
    baseline_to    TIMESTAMPTZ,
    summary        VARCHAR     NOT NULL,
    detail         JSON
);

-- Append-only time series. Never updated or deleted by this package.
CREATE TABLE reputation (
    indicator    VARCHAR     NOT NULL,
    verdict      VARCHAR     NOT NULL,
    observed_at  TIMESTAMPTZ NOT NULL,
    source       VARCHAR     NOT NULL
);
