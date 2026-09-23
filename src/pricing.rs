//! What the plane charges, and the monthly close that charges it.
//!
//! # The model
//!
//! `max(floor_micros, revenue_micros * rate_bps / 10_000)` per account per
//! calendar month, where `revenue_micros` is the account's own metered revenue:
//! the sum of what it charged *its* customers, which the plane already computes
//! into `usage_counters.spend_micros` for spend caps and had never read for its
//! own revenue.
//!
//! # Why this is a period and not a drip
//!
//! Upstream billing used to forward one meter event per processed unit, 1:1,
//! continuously. That cannot express a minimum: a floor is a property of a
//! period, and a drip has no periods. It also could not express a percentage,
//! because the rate lived in a Stripe dashboard object rather than here.
//!
//! The event ledger is unchanged and is still the audit trail. What became
//! period-grained is the *charge*.
//!
//! # What this model depends on
//!
//! A percentage of metered revenue is only meaningful when a customer's
//! `unit_price_micros` is truthful, because that declared price is what the
//! percentage is taken of. That is a commercial property of this pricing model,
//! not something code can enforce.

use axum::extract::State;
use axum::{Json, Router, routing};
use chrono::{DateTime, Datelike, TimeZone, Utc};
use mcp_usage_export::{AggregatedUsage, MeterEventOutcome};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row as _};

use crate::AppState;
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::export::Destination;

/// Basis points in one whole. 10,000 bps = 100%.
const BPS_DIVISOR: i128 = 10_000;

/// Millionths in one cent. Stripe meter values are integers, and cents is the
/// smallest unit money is actually denominated in.
const MICROS_PER_CENT: i128 = 10_000;

/// How far back a close will reach for unbilled periods.
///
/// Bounds the work a first run does on an account with a long history, and
/// keeps the close away from periods so old that Stripe would reject the event
/// anyway.
const MAX_PERIODS_PER_RUN: i64 = 3;

/// Per-account terms.
#[derive(Debug, Serialize)]
pub struct Pricing {
    /// Basis points of metered revenue. 150 = 1.5%.
    pub rate_bps: i32,
    /// Monthly minimum, in millionths.
    pub floor_micros: i64,
    /// When the terms begin applying.
    pub starts_at: DateTime<Utc>,
    /// When the terms stop applying.
    pub ends_at: Option<DateTime<Utc>>,
}

impl Pricing {
    /// Whether these terms cover the period `[start, end)`.
    ///
    /// Ordinary interval overlap, and the reason it is spelled out: the close
    /// walks back several finished periods, so terms agreed today would
    /// otherwise invoice an account a floor for each of the months before it
    /// had any terms at all.
    #[must_use]
    pub fn covers(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        self.starts_at < end && self.ends_at.is_none_or(|ends_at| ends_at > start)
    }
}

/// A request to set terms.
#[derive(Debug, Deserialize)]
pub struct SetPricing {
    /// Basis points of metered revenue, 0..=10000.
    pub rate_bps: i32,
    /// Monthly minimum, in millionths.
    pub floor_micros: i64,
    /// When the terms begin. Defaults to now; set it to backdate deliberately.
    #[serde(default)]
    pub starts_at: Option<DateTime<Utc>>,
    /// Optional end of the terms.
    #[serde(default)]
    pub ends_at: Option<DateTime<Utc>>,
}

/// One closed period.
#[derive(Debug, Serialize)]
pub struct Invoice {
    /// Start of the month.
    pub period_start: DateTime<Utc>,
    /// Start of the month after.
    pub period_end: DateTime<Utc>,
    /// The account's own metered revenue for the period.
    pub revenue_micros: i64,
    /// Units metered for it.
    pub units: i64,
    /// The rate applied.
    pub rate_bps: i32,
    /// The floor applied.
    pub floor_micros: i64,
    /// What the plane charged.
    pub charge_micros: i64,
    /// Whether the provider has accepted it.
    pub settled: bool,
}

/// Admin routes for terms and closed periods.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/pricing", routing::get(read).put(write))
        .route("/v1/pricing/invoices", routing::get(invoices))
}

/// The charge for a period, in millionths.
///
/// Integer throughout, via `i128` for the multiply: revenue in millionths times
/// ten thousand basis points overflows `i64` at around 92 million currency
/// units of revenue, which is not a ceiling to discover in production.
#[must_use]
pub fn charge_micros(revenue_micros: i64, rate_bps: i32, floor_micros: i64) -> i64 {
    let metered = i128::from(revenue_micros)
        .saturating_mul(i128::from(rate_bps))
        .saturating_div(BPS_DIVISOR);
    let floor = i128::from(floor_micros);
    i64::try_from(metered.max(floor)).unwrap_or(i64::MAX)
}

/// Millionths as whole cents, rounded half up.
///
/// Stripe meter values are integers. Rounding half up rather than truncating
/// means the error across many periods averages out instead of always falling
/// in the same direction.
#[must_use]
pub fn micros_to_cents(micros: i64) -> u64 {
    let cents = (i128::from(micros).saturating_add(MICROS_PER_CENT / 2)) / MICROS_PER_CENT;
    u64::try_from(cents).unwrap_or(0)
}

/// The month containing `at`, as `[start, end)`.
fn month_bounds(at: DateTime<Utc>) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let start = Utc
        .with_ymd_and_hms(at.year(), at.month(), 1, 0, 0, 0)
        .single()?;
    let (next_year, next_month) = if at.month() == 12 {
        (at.year() + 1, 1)
    } else {
        (at.year(), at.month() + 1)
    };
    let end = Utc
        .with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
        .single()?;
    Some((start, end))
}

/// The month before the one containing `at`.
fn previous_month(at: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let (start, _) = month_bounds(at)?;
    month_bounds(start.checked_sub_signed(chrono::Duration::days(1))?).map(|(start, _)| start)
}

async fn read(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Pricing>> {
    let row = sqlx::query(
        "SELECT rate_bps, floor_micros, starts_at, ends_at
         FROM plane_pricing WHERE account_id = $1",
    )
    .bind(&caller.account_id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(Json(match row {
        Some(row) => Pricing {
            rate_bps: row.try_get("rate_bps")?,
            floor_micros: row.try_get("floor_micros")?,
            starts_at: row.try_get("starts_at")?,
            ends_at: row.try_get("ends_at")?,
        },
        // No terms is not zero terms: it means nothing has been sold to this
        // account, and the close skips it entirely.
        None => Pricing {
            rate_bps: 0,
            floor_micros: 0,
            starts_at: Utc::now(),
            ends_at: None,
        },
    }))
}

async fn write(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Json(body): Json<SetPricing>,
) -> ApiResult<Json<Pricing>> {
    if !(0..=10_000).contains(&body.rate_bps) {
        return Err(ApiError::BadRequest(
            "rate_bps must be between 0 and 10000".to_owned(),
        ));
    }
    if body.floor_micros < 0 {
        return Err(ApiError::BadRequest(
            "floor_micros must not be negative".to_owned(),
        ));
    }

    sqlx::query(
        "INSERT INTO plane_pricing (account_id, rate_bps, floor_micros, starts_at, ends_at)
         VALUES ($1, $2, $3, COALESCE($4, NOW()), $5)
         ON CONFLICT (account_id) DO UPDATE
           SET rate_bps = EXCLUDED.rate_bps,
               floor_micros = EXCLUDED.floor_micros,
               starts_at = EXCLUDED.starts_at,
               ends_at = EXCLUDED.ends_at,
               updated_at = NOW()",
    )
    .bind(&caller.account_id)
    .bind(body.rate_bps)
    .bind(body.floor_micros)
    .bind(body.starts_at)
    .bind(body.ends_at)
    .execute(&state.pool)
    .await?;

    read(State(state), AdminCaller(caller)).await
}

async fn invoices(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Vec<Invoice>>> {
    let rows = sqlx::query(
        "SELECT period_start, period_end, revenue_micros, units, rate_bps,
                floor_micros, charge_micros, settled_at
         FROM plane_invoices
         WHERE account_id = $1
         ORDER BY period_start DESC
         LIMIT 120",
    )
    .bind(&caller.account_id)
    .fetch_all(&state.pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let settled_at: Option<DateTime<Utc>> = row.try_get("settled_at")?;
            Ok(Invoice {
                period_start: row.try_get("period_start")?,
                period_end: row.try_get("period_end")?,
                revenue_micros: row.try_get("revenue_micros")?,
                units: row.try_get("units")?,
                rate_bps: row.try_get("rate_bps")?,
                floor_micros: row.try_get("floor_micros")?,
                charge_micros: row.try_get("charge_micros")?,
                settled: settled_at.is_some(),
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

// ------------------------------------------------------------------ close

/// Close finished periods and charge for them, forever.
///
/// Runs on the same interval as the export drain. A close is cheap when there
/// is nothing to close - one query per account with terms - and closing early
/// and often means a period is invoiced shortly after it ends rather than
/// whenever someone remembers.
pub async fn close_forever(state: AppState, interval: std::time::Duration) {
    let destination = state.billing.destination();
    if matches!(destination, Destination::None) {
        tracing::info!("no plane Stripe key configured; period closing is idle");
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = close_all(&state, &destination).await {
            tracing::error!(%error, "period close failed");
        }
    }
}

async fn close_all(state: &AppState, destination: &Destination) -> Result<(), sqlx::Error> {
    // Only accounts with terms AND a customer to invoice. An account with terms
    // and no customer accrues periods it cannot be charged for, which shows up
    // as unsettled rows rather than as silence.
    let rows = sqlx::query(
        "SELECT p.account_id, p.rate_bps, p.floor_micros, p.starts_at, p.ends_at,
                b.stripe_customer_id
         FROM plane_pricing p
         JOIN account_billing b ON b.account_id = p.account_id
         WHERE b.stripe_customer_id IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let account_id: String = row.try_get("account_id")?;
        let terms = Pricing {
            rate_bps: row.try_get("rate_bps")?,
            floor_micros: row.try_get("floor_micros")?,
            starts_at: row.try_get("starts_at")?,
            ends_at: row.try_get("ends_at")?,
        };
        let customer: String = row.try_get("stripe_customer_id")?;
        if let Err(error) = close_account(state, destination, &account_id, &terms, &customer).await
        {
            tracing::error!(account_id, %error, "closing periods for an account failed");
        }
    }
    Ok(())
}

async fn close_account(
    state: &AppState,
    destination: &Destination,
    account_id: &str,
    terms: &Pricing,
    customer: &str,
) -> Result<(), sqlx::Error> {
    // Walk back from last month. Only finished periods are charged: the current
    // month is still accruing, and invoicing it would bill a partial period.
    let mut period = previous_month(Utc::now());
    for _ in 0..MAX_PERIODS_PER_RUN {
        let Some(start) = period else { break };
        let Some((_, end)) = month_bounds(start) else {
            break;
        };

        if !terms.covers(start, end) {
            if terms.starts_at >= end {
                // Terms began after this period ended, and every period before
                // it is older still.
                break;
            }
            // Terms have ended: skip this period but keep walking back, since
            // earlier ones may still be owed.
            period = previous_month(start);
            continue;
        }

        let recorded = record_period(&state.pool, account_id, terms, start, end).await?;
        if recorded {
            tracing::info!(account_id, %start, "closed a billing period");
        }
        period = previous_month(start);
    }

    settle_unsettled(state, destination, account_id, customer).await
}

/// Compute and store one period's charge, if it has not been stored already.
///
/// Returns whether a row was created. The `ON CONFLICT DO NOTHING` is the
/// idempotency: a period that already has an invoice is never recomputed, so
/// changing an account's rate cannot restate what it was already charged.
async fn record_period(
    pool: &PgPool,
    account_id: &str,
    terms: &Pricing,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let totals = sqlx::query(
        "SELECT COALESCE(SUM(spend_micros), 0)::bigint AS revenue_micros,
                COALESCE(SUM(units), 0)::bigint AS units
         FROM usage_counters
         WHERE account_id = $1 AND window_start = $2",
    )
    .bind(account_id)
    .bind(start)
    .fetch_one(pool)
    .await?;

    let revenue_micros: i64 = totals.try_get("revenue_micros")?;
    let units: i64 = totals.try_get("units")?;
    let charge = charge_micros(revenue_micros, terms.rate_bps, terms.floor_micros);

    // `YYYY-MM` rather than a timestamp: the identifier is what the provider
    // deduplicates on, so it has to be stable across retries and readable in a
    // Stripe dashboard.
    let identifier = format!("planeperiod:{account_id}:{}", start.format("%Y-%m"));

    let inserted = sqlx::query(
        "INSERT INTO plane_invoices
           (account_id, period_start, period_end, revenue_micros, units,
            rate_bps, floor_micros, charge_micros, identifier)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (account_id, period_start) DO NOTHING",
    )
    .bind(account_id)
    .bind(start)
    .bind(end)
    .bind(revenue_micros)
    .bind(units)
    .bind(terms.rate_bps)
    .bind(terms.floor_micros)
    .bind(charge)
    .bind(&identifier)
    .execute(pool)
    .await?;

    Ok(inserted.rows_affected() > 0)
}

/// Present every computed-but-undelivered charge to the billing provider.
async fn settle_unsettled(
    state: &AppState,
    destination: &Destination,
    account_id: &str,
    customer: &str,
) -> Result<(), sqlx::Error> {
    let Some(provider) = destination.provider(state.allow_loopback_destinations) else {
        return Ok(());
    };

    let rows = sqlx::query(
        "SELECT period_start, period_end, charge_micros, identifier
         FROM plane_invoices
         WHERE account_id = $1 AND settled_at IS NULL
         ORDER BY period_start",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let identifier: String = row.try_get("identifier")?;
        let charge_micros: i64 = row.try_get("charge_micros")?;
        let period_start: DateTime<Utc> = row.try_get("period_start")?;
        let period_end: DateTime<Utc> = row.try_get("period_end")?;
        let cents = micros_to_cents(charge_micros);

        // A period that came to nothing is settled without being sent. Stripe
        // would accept a zero-value event, but an invoice line for nothing is
        // noise in a place people read to answer billing questions.
        if cents == 0 {
            mark_settled(&state.pool, &identifier).await?;
            continue;
        }

        // Stamped at the period's end, so Stripe attributes the charge to the
        // period it is for rather than the one it was computed in. Stripe
        // rejects events older than 35 days, so a close that is very late
        // falls back to now and says so - a charge attributed to the wrong
        // period is recoverable, one that is refused outright is not.
        let now = Utc::now();
        let age = now.signed_duration_since(period_end);
        let timestamp = if age > chrono::Duration::days(34) {
            tracing::error!(
                account_id,
                %period_start,
                days_late = age.num_days(),
                "closing a period past Stripe's meter-event window; the charge \
                 will land in the current period instead of the one it is for"
            );
            now
        } else {
            period_end
        };

        let usage = AggregatedUsage {
            identifier: identifier.clone(),
            customer_id: customer.to_owned(),
            meter: state
                .billing
                .meter_name
                .clone()
                .unwrap_or_else(|| "mcp_usage_plane".to_owned()),
            units: cents,
            timestamp: u64::try_from(timestamp.timestamp()).unwrap_or_default(),
        };

        match provider.submit(std::slice::from_ref(&usage)).await {
            Ok(outcomes) => match outcomes.first() {
                Some(MeterEventOutcome::Accepted) => {
                    mark_settled(&state.pool, &identifier).await?;
                    tracing::info!(account_id, %period_start, cents, "charged a closed period");
                }
                Some(MeterEventOutcome::PermanentRejection { code }) => {
                    // Left unsettled on purpose. A permanently rejected charge
                    // is revenue that needs a person, and a row that stays
                    // unsettled is how it stays visible.
                    tracing::error!(
                        account_id,
                        %period_start,
                        code,
                        "the billing provider permanently rejected a period charge"
                    );
                }
                // Unmarked, so the next cycle presents it again with the same
                // identifier and the provider deduplicates.
                Some(MeterEventOutcome::RetryableFailure { .. }) | None => {}
            },
            Err(error) => {
                tracing::warn!(
                    account_id,
                    %period_start,
                    code = error.code(),
                    "period charge could not be delivered; it stays unsettled"
                );
            }
        }
    }
    Ok(())
}

async fn mark_settled(pool: &PgPool, identifier: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE plane_invoices SET settled_at = NOW() WHERE identifier = $1")
        .bind(identifier)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_applies_when_the_percentage_comes_to_less() {
        // The whole reason this is a period and not a drip.
        let floor = 49_000_000; // 49 currency units
        assert_eq!(charge_micros(0, 150, floor), floor, "no usage still owes");
        assert_eq!(
            charge_micros(1_000_000_000, 150, floor),
            floor,
            "1.5% of 1000 is 15, under the floor"
        );
    }

    #[test]
    fn the_percentage_applies_once_it_passes_the_floor() {
        let floor = 49_000_000;
        // 1.5% of 10,000 currency units is 150, over the floor.
        assert_eq!(charge_micros(10_000_000_000, 150, floor), 150_000_000);
    }

    #[test]
    fn the_rate_is_exact_integer_arithmetic() {
        // 200 bps of 12.345678 currency units. No floats anywhere: this
        // multiplies money, and a rounding nobody can reproduce from an
        // invoice is a support ticket.
        assert_eq!(charge_micros(12_345_678, 200, 0), 246_913);
        assert_eq!(charge_micros(0, 0, 0), 0);
    }

    #[test]
    fn a_large_revenue_does_not_overflow_the_multiply() {
        // Revenue in millionths times ten thousand basis points overflows i64
        // at around 92 million currency units, which is a ceiling nobody wants
        // to find in production.
        let huge = i64::MAX / 2;
        let charged = charge_micros(huge, 10_000, 0);
        assert_eq!(charged, huge, "100% of revenue is revenue");
    }

    #[test]
    fn cents_round_half_up_rather_than_always_down() {
        assert_eq!(micros_to_cents(0), 0);
        assert_eq!(micros_to_cents(9_999), 1, "just under a cent rounds to one");
        assert_eq!(micros_to_cents(10_000), 1);
        assert_eq!(micros_to_cents(14_999), 1);
        assert_eq!(micros_to_cents(15_000), 2, "exactly half rounds up");
        assert_eq!(micros_to_cents(49_000_000), 4_900);
    }

    #[test]
    fn terms_do_not_cover_periods_that_ended_before_they_began() {
        // The close walks back several finished periods. Without this, terms
        // agreed today invoice a floor for each of the months before them,
        // which is how a brand new account got charged three times over.
        let (jan_start, jan_end) =
            month_bounds(Utc.with_ymd_and_hms(2027, 1, 10, 0, 0, 0).unwrap()).unwrap();

        let agreed_in_february = Pricing {
            rate_bps: 150,
            floor_micros: 49_000_000,
            starts_at: Utc.with_ymd_and_hms(2027, 2, 3, 0, 0, 0).unwrap(),
            ends_at: None,
        };
        assert!(!agreed_in_february.covers(jan_start, jan_end));

        let agreed_in_december = Pricing {
            starts_at: Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap(),
            ..agreed_in_february
        };
        assert!(agreed_in_december.covers(jan_start, jan_end));

        // Beginning partway through a period still covers it: the floor is a
        // monthly minimum, not something prorated by the day.
        let agreed_mid_january = Pricing {
            starts_at: Utc.with_ymd_and_hms(2027, 1, 20, 0, 0, 0).unwrap(),
            ..agreed_in_february
        };
        assert!(agreed_mid_january.covers(jan_start, jan_end));
    }

    #[test]
    fn terms_stop_covering_once_they_have_ended() {
        let (jan_start, jan_end) =
            month_bounds(Utc.with_ymd_and_hms(2027, 1, 10, 0, 0, 0).unwrap()).unwrap();
        let ended_in_december = Pricing {
            rate_bps: 150,
            floor_micros: 0,
            starts_at: Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
            ends_at: Some(Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0).unwrap()),
        };
        assert!(!ended_in_december.covers(jan_start, jan_end));

        // Ending partway through still covers that period. An account that
        // churns mid-month owes the month it churned in.
        let ended_mid_january = Pricing {
            ends_at: Some(Utc.with_ymd_and_hms(2027, 1, 15, 0, 0, 0).unwrap()),
            ..ended_in_december
        };
        assert!(ended_mid_january.covers(jan_start, jan_end));
    }

    #[test]
    fn month_bounds_wrap_the_year() {
        let december = Utc.with_ymd_and_hms(2026, 12, 15, 9, 30, 0).unwrap();
        let (start, end) = month_bounds(december).expect("december has bounds");
        assert_eq!(start.to_rfc3339(), "2026-12-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2027-01-01T00:00:00+00:00");

        let january = Utc.with_ymd_and_hms(2027, 1, 3, 0, 0, 0).unwrap();
        assert_eq!(
            previous_month(january).expect("january has a predecessor"),
            start,
            "the month before January is the previous December"
        );
    }

    #[test]
    fn walking_back_from_march_crosses_into_the_previous_year() {
        let mut at = Utc.with_ymd_and_hms(2027, 3, 10, 0, 0, 0).unwrap();
        let mut seen = Vec::new();
        for _ in 0..4 {
            let previous = previous_month(at).expect("every month has a predecessor");
            seen.push(previous.format("%Y-%m").to_string());
            at = previous;
        }
        assert_eq!(seen, ["2027-02", "2027-01", "2026-12", "2026-11"]);
    }
}
