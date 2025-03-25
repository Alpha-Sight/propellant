use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use std::fmt;

//------------------------------------------------------------------------
// SUBSCRIPTION TIERS
//------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum SubscriptionTier {
    Free,                // Default tier (0 CVs)
    Basic,               // 1,500 XION = 1 CV
    Standard,            // 5,000 XION = 5 CVs
    Premium,             // 10,000 XION = 15 CVs
}

// Add Display implementation to convert to string
impl fmt::Display for SubscriptionTier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SubscriptionTier::Free => write!(f, "free"),
            SubscriptionTier::Basic => write!(f, "basic"),
            SubscriptionTier::Standard => write!(f, "standard"),
            SubscriptionTier::Premium => write!(f, "premium"),
        }
    }
}

// Helper to convert SubscriptionTier to string for storage keys
pub fn tier_to_key(tier: &SubscriptionTier) -> String {
    match tier {
        SubscriptionTier::Free => "free".to_string(),
        SubscriptionTier::Basic => "basic".to_string(),
        SubscriptionTier::Standard => "standard".to_string(),
        SubscriptionTier::Premium => "premium".to_string(),
    }
}

// Helper to convert string key back to SubscriptionTier
pub fn key_to_tier(key: &str) -> Option<SubscriptionTier> {
    match key {
        "free" => Some(SubscriptionTier::Free),
        "basic" => Some(SubscriptionTier::Basic),
        "standard" => Some(SubscriptionTier::Standard),
        "premium" => Some(SubscriptionTier::Premium),
        _ => None,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct TierConfig {
    tier: SubscriptionTier,
    price: Uint128,          // Price in XION
    cv_limit: u32,           // Number of CVs allowed
    treasury_address: Addr,  // Treasury contract address for this tier
}

impl TierConfig {
    pub fn new(tier: SubscriptionTier, price: Uint128, cv_limit: u32, treasury_address: Addr) -> Self {
        Self {
            tier,
            price,
            cv_limit,
            treasury_address,
        }
    }
    
    pub fn tier(&self) -> &SubscriptionTier {
        &self.tier
    }
    
    pub fn price(&self) -> Uint128 {
        self.price
    }
    
    pub fn cv_limit(&self) -> u32 {
        self.cv_limit
    }
    
    pub fn treasury_address(&self) -> &Addr {
        &self.treasury_address
    }
    
    pub fn set_price(&mut self, price: Uint128) {
        self.price = price;
    }
    
    pub fn set_cv_limit(&mut self, cv_limit: u32) {
        self.cv_limit = cv_limit;
    }
    
    pub fn set_treasury_address(&mut self, treasury_address: Addr) {
        self.treasury_address = treasury_address;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct UserSubscription {
    tier: SubscriptionTier,
    cvs_generated: u32,       // Number of CVs already generated
    expiration: u64,          // Timestamp when subscription expires
    treasury_linked: bool,      // Whether user is linked to treasury
    last_reset_time: u64,  
    signature: Option<String>, // Add this field  
}

impl UserSubscription {
    pub fn new(tier: SubscriptionTier, cvs_generated: u32, expiration: u64, treasury_linked: bool, last_reset_time: u64, signature: Option<String>) -> Self {
        Self {
            tier,
            cvs_generated,
            expiration,
            treasury_linked,
            last_reset_time,
            signature,
        }
    }
    
    pub fn tier(&self) -> &SubscriptionTier {
        &self.tier
    }

    pub fn cvs_generated(&self) -> u32 {
        self.cvs_generated
    }

    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    pub fn treasury_linked(&self) -> bool {
        self.treasury_linked
    }

    pub fn last_reset_time(&self) -> u64 {
        self.last_reset_time
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    pub fn set_cvs_generated(&mut self, cvs_generated: u32) {
        self.cvs_generated = cvs_generated;
    }

    pub fn set_expiration(&mut self, expiration: u64) {
        self.expiration = expiration;
    }

    pub fn set_treasury_linked(&mut self, treasury_linked: bool) {
        self.treasury_linked = treasury_linked;
    }

    pub fn set_last_reset_time(&mut self, last_reset_time: u64) {
        self.last_reset_time = last_reset_time;
    }

    pub fn set_signature(&mut self, signature: Option<String>) {
        self.signature = signature;
    }
}

//------------------------------------------------------------------------
// USER ACCOUNT MANAGEMENT
//------------------------------------------------------------------------

/// User registration and profile information
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct User {
    address: Addr,                   // User's blockchain wallet address
    email: String,                   // User's email address
    email_verified: bool,            // Whether email has been verified
    registration_date: u64,          // When user registered (timestamp)
    last_login: u64,                 // When user last logged in (timestamp)
    name: Option<String>,            // User's display name (optional)
    subscription: UserSubscription,  // User's subscription details
}

impl User {
    pub fn new(address: Addr, email: String, email_verified: bool, registration_date: u64, last_login: u64, name: Option<String>, subscription: UserSubscription) -> Self {
        Self {
            address,
            email,
            email_verified,
            registration_date,
            last_login,
            name,
            subscription,
        }
    }

    pub fn address(&self) -> &Addr {
        &self.address
    }

    pub fn email(&self) -> &String {
        &self.email
    }

    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    pub fn registration_date(&self) -> u64 {
        self.registration_date
    }

    pub fn last_login(&self) -> u64 {
        self.last_login
    }

    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    pub fn subscription(&self) -> &UserSubscription {
        &self.subscription
    }

    pub fn set_email_verified(&mut self, email_verified: bool) {
        self.email_verified = email_verified;
    }

    pub fn set_email(&mut self, email: String) {
        self.email = email;
    }

    pub fn set_last_login(&mut self, last_login: u64) {
        self.last_login = last_login;
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    pub fn set_subscription(&mut self, subscription: UserSubscription) {
        self.subscription = subscription;
    }

    pub fn subscription_mut(&mut self) -> &mut UserSubscription {
        &mut self.subscription
    }
}

//------------------------------------------------------------------------
// CONTRACT CONFIGURATION
//------------------------------------------------------------------------

/// Global contract configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Config {
    admin: Addr,                     // Contract administrator
    burnt_wallet_api_key: String,    // API key for Burnt wallet integration
    treasury_admin: Addr,            // Admin address for treasury operations
}

impl Config {
    pub fn new(admin: Addr, burnt_wallet_api_key: String, treasury_admin: Addr) -> Self {
        Self {
            admin,
            burnt_wallet_api_key,
            treasury_admin,
        }
    }

    pub fn admin(&self) -> &Addr {
        &self.admin
    }

    pub fn burnt_wallet_api_key(&self) -> &String {
        &self.burnt_wallet_api_key
    }

    pub fn treasury_admin(&self) -> &Addr {
        &self.treasury_admin
    }

    pub fn set_admin(&mut self, admin: Addr) {
        self.admin = admin;
    }

    pub fn set_burnt_wallet_api_key(&mut self, api_key: String) {
        self.burnt_wallet_api_key = api_key;
    }

    pub fn set_treasury_admin(&mut self, treasury_admin: Addr) {
        self.treasury_admin = treasury_admin;
    }
}

//------------------------------------------------------------------------
// STORAGE DEFINITIONS
//------------------------------------------------------------------------

// Contract configuration
pub const CONFIG: Item<Config> = Item::new("config");

// User management
pub const USERS: Map<&Addr, User> = Map::new("users");
pub const EMAIL_TO_ADDR: Map<&str, Addr> = Map::new("email_to_addr");

// Subscription tiers - now using &str keys instead of enum directly
pub const TIER_CONFIGS: Map<&str, TierConfig> = Map::new("tier_configs");

// Statistics
pub const TOTAL_USERS: Item<u64> = Item::new("total_users");
pub const TOTAL_PAID_USERS: Map<&str, u64> = Map::new("total_paid_users");

// Add this to your state.rs file
pub const LAST_GLOBAL_RESET: Item<u64> = Item::new("last_global_reset");

// Add this to your state.rs file
pub const TOTAL_CVS: Item<u64> = Item::new("total_cv");


#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128};

    #[test]
    fn test_config_state() {
        let mut deps = mock_dependencies();
        let config = Config::new(
            Addr::unchecked("admin"),
            "key".to_string(),
            Addr::unchecked("treasury"),
        );

        CONFIG.save(&mut deps.storage, &config).unwrap();
        let loaded = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config, loaded);
    }

    #[test]
    fn test_tier_config_state() {
        let mut deps = mock_dependencies();
        let tier_config = TierConfig::new(
            SubscriptionTier::Premium,
            Uint128::new(10000),
            15,
            Addr::unchecked("treasury"),
        );

        TIER_CONFIGS.save(&mut deps.storage, &tier_to_key(&tier_config.tier()), &tier_config).unwrap();
        let loaded = TIER_CONFIGS.load(&deps.storage, &tier_to_key(&tier_config.tier())).unwrap();
        assert_eq!(tier_config, loaded);
    }

    #[test]
    fn test_total_users_state() {
        let mut deps = mock_dependencies();
        let total_users: u64 = 0;

        TOTAL_USERS.save(&mut deps.storage, &total_users).unwrap();
        let loaded: u64 = TOTAL_USERS.load(&deps.storage).unwrap();
        assert_eq!(total_users, loaded);
    }

    #[test]
    fn test_user_state() {
        let mut deps = mock_dependencies();
        let subscription = UserSubscription::new(
            SubscriptionTier::Standard,
            3,
            1627849600,
            true,
            1625247600,
            Some("sdw1323emfc23ncwksnc293enfc29efcn29iecn".to_string()),
        );

        let user = User::new(
            Addr::unchecked("user1"),
            "user1@example.com".to_string(),
            true,
            1625247600,
            1625247600,
            Some("User One".to_string()),
            subscription,
        );

        USERS.save(&mut deps.storage, &user.address(), &user).unwrap();
        let loaded = USERS.load(&deps.storage, &user.address()).unwrap();
        assert_eq!(user, loaded);

        EMAIL_TO_ADDR.save(&mut deps.storage, &user.email(), &user.address()).unwrap();
        let loaded_address = EMAIL_TO_ADDR.load(&deps.storage, &user.email()).unwrap();
        assert_eq!(user.address(), &loaded_address);
    }
}