-- v3: the sources that returned a stored document, when more than one source of a scope
-- did and it was stored once (under events.source). NULL means only events.source did.
-- A detector scoped to one of the others reads the document through this column, in a
-- later hunt as well as the one that stored it.
ALTER TABLE events ADD COLUMN returners VARCHAR[];
