use cosmwasm_std::{Addr, Attribute, DepsMut, Env, MessageInfo, StdError, StdResult, Uint128};
// use chrono::{DateTime, Utc};
use chrono::{DateTime, Datelike, TimeZone, Utc};

use crate::state::LAST_GLOBAL_RESET;


/// Generate a standardized log entry with user and timestamp
pub fn create_log_entry(env: &Env, user: &Addr) -> Vec<Attribute> {
    // Get current blockchain timestamp
    let timestamp_seconds = env.block.time.seconds();
    
    // Format timestamp dynamically (current time: 2025-03-20 10:33:29)
    let formatted_timestamp = format_timestamp(timestamp_seconds);
    
    vec![
        Attribute::new("timestamp_seconds", timestamp_seconds.to_string()),
        Attribute::new("formatted_timestamp", formatted_timestamp),
        Attribute::new("user", user.to_string()),
    ]
}

/// Format a Unix timestamp into "YYYY-MM-DD HH:MM:SS" format
fn format_timestamp(timestamp: u64) -> String {
    // Convert Unix timestamp to DateTime using non-deprecated function
    let datetime = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
    
    // Format as YYYY-MM-DD HH:MM:SS 
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

// Helper function to check if we need a global reset
pub fn check_global_reset(deps: &mut DepsMut, env: &Env) -> StdResult<bool> {
    let now = env.block.time.seconds();
    let last_reset = LAST_GLOBAL_RESET.load(deps.storage)?;
    
    // Convert timestamps to DateTime objects
    let last_reset_dt = Utc.timestamp_opt(last_reset as i64, 0).single().unwrap_or_else(|| Utc::now());
    let current_dt = Utc.timestamp_opt(now as i64, 0).single().unwrap_or_else(|| Utc::now());
    
    // If we've entered a new month
    if last_reset_dt.month() != current_dt.month() || last_reset_dt.year() != current_dt.year() {
        // Update the global reset time
        LAST_GLOBAL_RESET.save(deps.storage, &now)?;
        return Ok(true);
    }
    
    Ok(false)
}


// fn timestamp_to_readable_time(timestamp: i64) -> String {
//     let naive_datetime = NaiveDateTime::from_timestamp(timestamp, 0);
//     let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
//     datetime.format("%Y-%m-%d %H:%M:%S").to_string()
// }

// fn main() {
//     let registration_date: i64 = 1625247600;
//     let last_login: i64 = 1625247600;

//     let readable_registration_date = timestamp_to_readable_time(registration_date);
//     let readable_last_login = timestamp_to_readable_time(last_login);

//     println!("Registration Date: {}", readable_registration_date);
//     println!("Last Login: {}", readable_last_login);
// }

/// Simple email validation for redundant safety
/// Note: Primary email verification happens via Burnt wallet/Abstraxion
pub fn is_valid_email(email: &str) -> bool {
    // This is a backup validation only - the Burnt wallet/Abstraxion 
    // has already verified the email by the time it reaches our contract
    // We keep this basic check for defensive programming practices
    email.contains('@') && email.contains('.')
}

/// Our own implementation of must_pay to avoid version conflicts
pub fn check_payment(info: &MessageInfo, denom: &str) -> StdResult<Uint128> {
    // Find the coin with matching denomination
    if let Some(coin) = info.funds.iter().find(|c| c.denom == denom) {
        if coin.amount.is_zero() {
            return Err(StdError::generic_err(format!("Zero amount for {}", denom)));
        }
        Ok(coin.amount)
    } else {
        Err(StdError::generic_err(format!("No funds sent with denomination {}", denom)))
    }
}