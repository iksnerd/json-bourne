-- v2: a run record can say its events were pruned (`jb db prune`). NULL means the
-- events are as they were saved. Findings and the run record itself stay unless the
-- prune was asked to drop them.
ALTER TABLE runs ADD COLUMN pruned_at TIMESTAMPTZ;
