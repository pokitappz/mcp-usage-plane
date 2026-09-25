-- The access queue goes with the marketing site.
--
-- `access_requests` was fed by exactly one thing: the form on the landing page,
-- which now lives in a separate repository as static HTML and sends an email
-- instead. A table nothing can write to is a table that only confuses whoever
-- reads the schema next.
--
-- What it was really providing was a way to create the first person on a
-- deployment, since nothing else wrote a `users` row. `POST /v1/accounts` takes
-- an `owner_email` now and does that directly, which is a shorter path to the
-- same place and does not require a queue to hold one row.

DROP TABLE IF EXISTS access_requests;
