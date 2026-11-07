-- v4: the durable identity of a shared document: a digest of its source scope and
-- DocKey, set only when several sources of one scope could return it. The reader's
-- dedupe uses it in place of (source, kind), so one document is one event whichever
-- of those sources stored it. NULL (every older row, every keyless event) keeps the
-- (source, kind) identity.
ALTER TABLE events ADD COLUMN doc_ident VARCHAR;
