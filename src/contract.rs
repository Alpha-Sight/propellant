
use cosmwasm_std::{
    entry_point, to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, Event, MessageInfo, Response, StdError, StdResult, Uint128
};
use sha2::{Sha256, Digest};

// use crate::auth::jwt::verify;
use crate::error::ContractError;
use cw2::set_contract_version;
// use sha2::{Sha256, Digest};
use crate::helpers::{check_global_reset, check_payment, create_log_entry, is_valid_email};
use crate::msg::{
    AllTierConfigsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, QueryMsg,
    TierConfigResponse, TotalUsersResponse, UserAddressResponse, UserResponse,
    UserSubscriptionResponse,
};
use crate::state::{
    tier_to_key, Config, SubscriptionTier, TierConfig, User, UserSubscription, CONFIG, EMAIL_TO_ADDR, LAST_GLOBAL_RESET, TIER_CONFIGS, TOTAL_CVS, TOTAL_PAID_USERS, TOTAL_USERS, USERS
};

const CONTRACT_NAME: &str = "crates.io:propellant_Dapp";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");


// Contract instantiation - save initial state
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Set the admin (either from message or default to sender)
    let admin = match msg.admin {
        Some(admin) => deps.api.addr_validate(&admin)?,
        None => info.sender.clone(),
    };

    // Set treasury admin (either from message or use regular admin)
    let treasury_admin = match msg.treasury_admin {
        Some(treasury_admin) => deps.api.addr_validate(&treasury_admin)?,
        None => admin.clone(),
    };

    // Store the configuration
    let mut config = Config::new(admin.clone(), msg.burnt_wallet_api_key, treasury_admin);
    CONFIG.save(deps.storage, &config)?;

    // Initialize total users counter
    TOTAL_USERS.save(deps.storage, &0u64)?;

    // Initialize the global reset timestamp
    let now = env.block.time.seconds();
    LAST_GLOBAL_RESET.save(deps.storage, &now)?;

    // Initialize total CV counter
    TOTAL_CVS.save(deps.storage, &0u64)?;

    // Set up default subscription tiers
    let default_treasury = admin.clone();

    // Create the Free tier
    let free_tier = TierConfig::new(
        SubscriptionTier::Free,
        Uint128::zero(),
        2, // 2 free credits per month
        default_treasury.clone(),
    );

    // Use tier_to_key for string conversion
    let free_key = tier_to_key(&SubscriptionTier::Free);
    TIER_CONFIGS.save(deps.storage, &free_key, &free_tier)?;

    // Add placeholders for other tiers (to be configured properly by admin later)
    for tier in [
        SubscriptionTier::Basic,
        SubscriptionTier::Standard,
        SubscriptionTier::Premium,
    ] {
        let placeholder_config = TierConfig::new(
            tier.clone(),
            Uint128::zero(), // Will be set by admin
            0,               // Will be set by admin
            default_treasury.clone(),
        );
        let tier_key = tier_to_key(&tier);
        TIER_CONFIGS.save(deps.storage, &tier_key, &placeholder_config)?;
    }

    // Log who initialized the contract and when
    let log_entry = create_log_entry(&env, &admin);

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let response = Response::new()
        .add_attribute("action", "instantiate")
        .add_attributes(log_entry);

    Ok(response)
}

// Execute entry point - handle messages
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // Admin functions
        ExecuteMsg::UpdateConfig {
            new_admin,
            burnt_wallet_api_key,
            treasury_admin,
        } => execute_update_config(
            deps,
            env,
            info,
            new_admin,
            burnt_wallet_api_key,
            treasury_admin,
        ),
        ExecuteMsg::ConfigureTier {
            tier,
            price,
            cv_limit,
            treasury_address,
        } => execute_configure_tier(deps, env, info, tier, price, cv_limit, treasury_address),

        // User management
        ExecuteMsg::RegisterUser { email, name } => {
            execute_register_user(deps, env, info, email, name)
        }
        ExecuteMsg::UpdateLastLogin {} => execute_update_last_login(deps, env, info),
        ExecuteMsg::UpdateUserProfile { name, email } => {
            execute_update_profile(deps, env, info, name, email)
        }

        // Subscription management
        ExecuteMsg::Subscribe { tier } => execute_subscribe(deps, env, info, tier),
        ExecuteMsg::LinkUserToTreasury { user_address } => {
            execute_link_user_to_treasury(deps, env, info, user_address)
        }
        ExecuteMsg::RecordCvGeneration { user_address } => {
            execute_record_cv_generation(deps, env, info, user_address)
        }
        ExecuteMsg::DeductCvCredit { user_address, signature } => {
            execute_deduct_cv_credit(deps, env, info, user_address, signature)
        }

        // JWT verification (uncomment if still needed)
        // ExecuteMsg::VerifyJWT { message, signature, audience, subject } => {
        //     execute_verify_jwt(deps, env, info, message, signature, audience, subject)
        // }
    }
}

pub fn execute_register_user(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    email: String,
    name: Option<String>,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Basic validation - still good to have
    if !is_valid_email(&email) {
        return Err(ContractError::InvalidEmail {});
    }

    // Check if email is already registered
    if EMAIL_TO_ADDR.may_load(deps.storage, &email)?.is_some() {
        return Err(ContractError::EmailAlreadyRegistered {});
    }

    // Check if wallet address is already registered
    if USERS.may_load(deps.storage, &sender)?.is_some() {
        return Err(ContractError::WalletAlreadyRegistered {});
    }

    // Current timestamp
    let now = env.block.time.seconds();

    // Load the Free tier config using string key
    let free_key = tier_to_key(&SubscriptionTier::Free);
    let _free_tier_config = TIER_CONFIGS.load(deps.storage, &free_key)?;

    // Create free subscription for the user
    let subscription = UserSubscription::new(
        SubscriptionTier::Free,
        0,
        u64::MAX,   // Free tier doesn't expire
        false,      // Not linked to treasury yet
        now,        // Set initial reset time to now
        None,
    );

    // Create new user with free subscription
    let user = User::new(
        sender.clone(),
        email.clone(),
        true, // Pre-verified by Abstraxion/Burnt wallet
        now,
        now,
        name,
        subscription,
    );


    // Save user data
    USERS.save(deps.storage, &sender, &user)?;
    EMAIL_TO_ADDR.save(deps.storage, &email, &sender)?;

    // Increment user counter
    let total_users = TOTAL_USERS.load(deps.storage)? + 1;
    TOTAL_USERS.save(deps.storage, &total_users)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "register_user")
        .add_attribute("email", email)
        .add_attribute("tier", "Free")
        .add_attributes(log_entry))
}

// Update config - admin only
pub fn execute_update_config(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    new_admin: Option<String>,
    burnt_wallet_api_key: Option<String>,
    treasury_admin: Option<String>,
) -> Result<Response, ContractError> {
    // Load config and check admin authorization
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != *config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Update admin if provided
    if let Some(new_admin) = new_admin {
        config.set_admin(deps.api.addr_validate(&new_admin)?);
    }

    // Update Burnt wallet API key if provided
    if let Some(burnt_wallet_api_key) = burnt_wallet_api_key {
        config.set_burnt_wallet_api_key(burnt_wallet_api_key);
    }

    // Update treasury admin if provided
    if let Some(treasury_admin) = treasury_admin {
        config.set_treasury_admin(deps.api.addr_validate(&treasury_admin)?);
    }

    // Save updated config
    CONFIG.save(deps.storage, &config)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &info.sender);

    Ok(Response::new()
        .add_attribute("action", "update_config")
        .add_attributes(log_entry))
}

// Function to handle JWT verification
// pub fn execute_verify_jwt(
//     deps: DepsMut,
//     env: Env,
//     info: MessageInfo,
//     message: String,
//     signature: String,
//     audience: String,
//     subject: String,
// ) -> Result<Response, ContractError> {
//     // Convert inputs to byte arrays
//     let message_bytes = message.as_bytes().to_vec();
//     let signature_bytes = base64::decode_config(&signature, base64::URL_SAFE_NO_PAD)?;
//     let tx_hash = sha256::digest_bytes(&message_bytes);

//     // Call the verify function from jwt.rs
//     verify(deps.as_ref(), &tx_hash, &signature_bytes, &audience, &subject)?;

//     // Log the verification action
//     let log_entry = create_log_entry(&env, &info.sender);

//     Ok(Response::new()
//         .add_attribute("action", "verify_jwt")
//         .add_attribute("message", message)
//         .add_attribute("audience", audience)
//         .add_attribute("subject", subject)
//         .add_attributes(log_entry))
// }

// Configure subscription tier (admin only)
pub fn execute_configure_tier(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tier: SubscriptionTier,
    price: Uint128,
    cv_limit: u32,
    treasury_address: String,
) -> Result<Response, ContractError> {
    // Check admin authorization
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Validate treasury address
    let treasury_addr = deps.api.addr_validate(&treasury_address)?;

    // Create or update tier configuration
    let mut tier_config = TierConfig::new(
        tier.clone(),
        price,
        cv_limit,
        treasury_addr.clone(),
    );

    // Convert tier to string key for storage
    let tier_key = tier_to_key(&tier);

    // Save tier configuration
    TIER_CONFIGS.save(deps.storage, &tier_key, &tier_config)?;

    // Log tier configuration
    Ok(Response::new()
        .add_attribute("action", "configure_tier")
        .add_attribute("tier", format!("{:?}", tier))
        .add_attribute("price", price.to_string())
        .add_attribute("cv_limit", cv_limit.to_string())
        .add_attribute("treasury_address", treasury_addr.to_string()))
}

// Record a CV generation (authorized users only)
pub fn execute_record_cv_generation(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
) -> Result<Response, ContractError> {
    // Get config
    let config = CONFIG.load(deps.storage)?;

    // Check if we need a global reset (first transaction of a new month)
    let global_reset = check_global_reset(&mut deps, &env)?;

    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;

    // If global reset happened and user is on free tier, reset their credits
    let mut user_reset = false;
    if global_reset && matches!(user.subscription().tier(), SubscriptionTier::Free) {
        user.subscription_mut().set_cvs_generated(0);
        user_reset = true;
    }

    // Get user's tier config using string key
    let tier_key = tier_to_key(&user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Check if caller is authorized (user themselves, admin, or the treasury)
    let is_authorized = info.sender == user_addr
        || info.sender == config.admin()
        || info.sender == tier_config.treasury_address();

    if !is_authorized {
        return Err(ContractError::Unauthorized {});
    }

    // Check if user's subscription is expired
    let now = env.block.time.seconds();
    if now > user.subscription().expiration() {
        return Err(ContractError::Std(StdError::generic_err(
            "Subscription expired",
        )));
    }

    // Check if user has reached CV limit
    if user.subscription().cvs_generated() >= tier_config.cv_limit() && tier_config.cv_limit() > 0 {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "CV limit reached: {}. Next reset on the 1st of the month.",
            tier_config.cv_limit()
        ))));
    }

    // Generate a hash signature for the CV request
    let mut hasher = Sha256::new();
    hasher.update(user_addr.as_bytes());
    hasher.update(now.to_string().as_bytes());
    let signature = hasher.finalize();
    let signature_hex = hex::encode(signature);

    // Store the signature associated with the user
    user.subscription_mut().set_signature(Some(signature_hex.clone()));
    USERS.save(deps.storage, &user_addr, &user)?;

    // Emit an event with the hash signature
    let event = Event::new("cv_request")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("signature", signature_hex.clone());

    Ok(Response::new()
        .add_event(event)
        .add_attribute("action", "record_cv_generation")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("tier", format!("{:?}", user.subscription().tier()))
        .add_attribute("cv_count", user.subscription().cvs_generated().to_string())
        .add_attribute("cv_limit", tier_config.cv_limit().to_string())
        .add_attribute("remaining_credits", 
            (tier_config.cv_limit() - user.subscription().cvs_generated()).to_string())
        .add_attribute("signature", signature_hex)
        .add_attribute("global_reset", global_reset.to_string())
        .add_attribute("credits_reset", user_reset.to_string()))
}

// Deduct user credit after CV generation (backend confirmation)
pub fn execute_deduct_cv_credit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
    signature: String,
) -> Result<Response, ContractError> {
    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;

    // Verify the signature
    if user.subscription().signature() != Some(signature.clone()) {
        return Err(ContractError::Unauthorized {});
    }

    // Ensure user has remaining credits
    if user.subscription().cvs_generated() == 0 {
        return Err(ContractError::Std(StdError::generic_err("No remaining credits")));
    }

    // Deduct one credit
    let cvs_generated = user.subscription().cvs_generated() - 1;
    user.subscription_mut().set_cvs_generated(cvs_generated);

    // Save updated user data
    USERS.save(deps.storage, &user_addr, &user)?;

    // Increment the total CV count in the app
    let total_cvs = TOTAL_CVS.load(deps.storage)? + 1;
    TOTAL_CVS.save(deps.storage, &total_cvs)?;

    Ok(Response::new()
        .add_attribute("action", "deduct_cv_credit")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("cv_count", cvs_generated.to_string())
        .add_attribute("total_cvs", total_cvs.to_string()))
}

// Subscribe to a paid tier - requires payment
pub fn execute_subscribe(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tier: SubscriptionTier,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Check if the requested tier is Free - can't "subscribe" to free tier
    if matches!(tier, SubscriptionTier::Free) {
        return Err(ContractError::Std(StdError::generic_err(
            "Cannot subscribe to Free tier, it's the default tier",
        )));
    }

    // Load tier configuration using string key
    let tier_key = tier_to_key(&tier);
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Check if user has sent enough payment - Using our custom checker
    let payment = check_payment(&info, "uxion").map_err(|e| ContractError::Std(e))?;

    if payment < tier_config.price() {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "Insufficient payment. Required: {} uxion, Received: {} uxion",
            tier_config.price(), payment
        ))));
    }

    // Forward payment to tier's treasury
    let forward_msg = BankMsg::Send {
        to_address: tier_config.treasury_address().to_string(),
        amount: vec![Coin {
            denom: "uxion".to_string(),
            amount: payment,
        }],
    };

    // Current timestamp
    let now = env.block.time.seconds();

    // Set expiration (30 days from now)
    let expiration = now + 30 * 24 * 60 * 60;

    // Get old tier key for stats update
    let old_tier_key = tier_to_key(&user.subscription().tier());

    // Update user's subscription
    let old_tier = user.subscription().tier().clone();
    user.set_subscription(UserSubscription::new(
        tier.clone(),
        0, // Reset on new subscription
        expiration,
        false, // Will be linked separately
        now,
        None,
    ));

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Update tier statistics
    if !matches!(old_tier, SubscriptionTier::Free) {
        // Decrement old tier counter if not free
        let mut old_tier_count = TOTAL_PAID_USERS
            .load(deps.storage, &old_tier_key)
            .unwrap_or(0);
        if old_tier_count > 0 {
            old_tier_count -= 1;
            TOTAL_PAID_USERS.save(deps.storage, &old_tier_key, &old_tier_count)?;
        }
    }

    // Increment new tier counter
    let new_tier_count = TOTAL_PAID_USERS.load(deps.storage, &tier_key).unwrap_or(0) + 1;
    TOTAL_PAID_USERS.save(deps.storage, &tier_key, &new_tier_count)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_message(forward_msg)
        .add_attribute("action", "subscribe")
        .add_attribute("tier", format!("{:?}", tier))
        .add_attribute("payment", payment.to_string())
        .add_attribute("expiration", expiration.to_string())
        .add_attributes(log_entry))
}

// Update user's last login timestamp
pub fn execute_update_last_login(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Update last login timestamp
    let now = env.block.time.seconds();
    user.set_last_login(now);

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "update_last_login")
        .add_attribute("user", sender.to_string())
        .add_attribute("timestamp", now.to_string())
        .add_attributes(log_entry))
}

// Update user profile information
pub fn execute_update_profile(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    name: Option<String>,
    email: Option<String>,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Update email if provided
    if let Some(new_email) = email {
        // Validate email format
        if !is_valid_email(&new_email) {
            return Err(ContractError::InvalidEmail {});
        }

        // Check if new email is already registered
        if new_email != *user.email() {
            if let Some(_) = EMAIL_TO_ADDR.may_load(deps.storage, &new_email)? {
                return Err(ContractError::EmailAlreadyRegistered {});
            }

            // Remove old email mapping
            EMAIL_TO_ADDR.remove(deps.storage, &user.email());

            // Add new email mapping
            EMAIL_TO_ADDR.save(deps.storage, &new_email, &sender)?;

            // Update user's email
            user.set_email(new_email);
            // Keep email verified status (pre-verified by integration)
            user.set_email_verified(true);
        }
    }

    // Update name if provided
    if let Some(new_name) = name {
        user.set_name(Some(new_name));
    }

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "update_profile")
        .add_attributes(log_entry))
}

// Link user to treasury (treasury admin only)
pub fn execute_link_user_to_treasury(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
) -> Result<Response, ContractError> {
    // Check treasury admin authorization
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.treasury_admin() && info.sender != config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;

    // Check if user is on a paid tier
    if matches!(user.subscription().tier(), SubscriptionTier::Free) {
        return Err(ContractError::Std(StdError::generic_err(
            "Cannot link free tier users to treasury",
        )));
    }

    // Mark user as linked to treasury
    // user.subscription.set_treasury_linked(true);
    user.subscription_mut().set_treasury_linked(true);


    // Save updated user data
    USERS.save(deps.storage, &user_addr, &user)?;

    // Log the action
    let log_entry = create_log_entry(&env, &info.sender);

    Ok(Response::new()
        .add_attribute("action", "link_user_to_treasury")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("tier", format!("{:?}", user.subscription().tier()))
        .add_attributes(log_entry))
}

//==================================================

                // Query contract

//===================================================
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetUser { address } => to_json_binary(&query_user(deps, address)?),
        QueryMsg::GetUserByEmail { email } => to_json_binary(&query_user_by_email(deps, email)?),
        QueryMsg::GetTotalUsers {} => to_json_binary(&query_total_users(deps)?),
        QueryMsg::GetTierConfig { tier } => to_json_binary(&query_tier_config(deps, tier)?),
        QueryMsg::GetAllTierConfigs {} => to_json_binary(&query_all_tier_configs(deps)?),
        QueryMsg::GetUserSubscription { address } => {
            to_json_binary(&query_user_subscription(deps, address)?)
        }
    }
}

// Get user subscription details
pub fn query_user_subscription(deps: Deps, address: String) -> StdResult<UserSubscriptionResponse> {
    let addr = deps.api.addr_validate(&address)?;

    let user = USERS.load(deps.storage, &addr)?;
    let tier_key = tier_to_key(&user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    Ok(UserSubscriptionResponse {
        subscription: user.subscription().clone(),
        tier_config,
    })
}

// Get contract configuration
pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    Ok(ConfigResponse {
        admin: config.admin().clone(),
        burnt_wallet_api_key: config.burnt_wallet_api_key().clone(),
        treasury_admin: config.treasury_admin().clone(),
    })
}

// Query user by address
pub fn query_user(deps: Deps, address: Option<String>) -> StdResult<UserResponse> {
    let addr = match address {
        Some(addr) => deps.api.addr_validate(&addr)?,
        None => return Err(StdError::generic_err("User address is required")),
    };

    let user = USERS.may_load(deps.storage, &addr)?;

    Ok(UserResponse { user })
}

// Find user address by email
pub fn query_user_by_email(deps: Deps, email: String) -> StdResult<UserAddressResponse> {
    let address = EMAIL_TO_ADDR.may_load(deps.storage, &email)?;

    Ok(UserAddressResponse { address })
}

// Get total users count
pub fn query_total_users(deps: Deps) -> StdResult<TotalUsersResponse> {
    let total_users = TOTAL_USERS.load(deps.storage)?;

    Ok(TotalUsersResponse { total_users })
}

// Get tier configuration
pub fn query_tier_config(deps: Deps, tier: SubscriptionTier) -> StdResult<TierConfigResponse> {
    let tier_key = tier_to_key(&tier);
    let config = TIER_CONFIGS.load(deps.storage, &tier_key)?;
    Ok(TierConfigResponse { config })
}

// Get all tier configs
pub fn query_all_tier_configs(deps: Deps) -> StdResult<AllTierConfigsResponse> {
    let tiers = [
        SubscriptionTier::Free,
        SubscriptionTier::Basic,
        SubscriptionTier::Standard,
        SubscriptionTier::Premium,
    ];

    let mut configs = Vec::new();

    for tier in tiers.iter() {
        let key = tier_to_key(tier);
        if let Ok(config) = TIER_CONFIGS.load(deps.storage, &key) {
            configs.push((tier.clone(), config));
        }
    }

    Ok(AllTierConfigsResponse { configs })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, message_info};
    use cosmwasm_std::{attr, from_json, Addr, Uint128};

    use crate::contract::{instantiate, query};
    use crate::msg::{ConfigResponse, InstantiateMsg, QueryMsg, TotalUsersResponse, UserAddressResponse, UserResponse};
    use crate::state::{tier_to_key, Config, SubscriptionTier, TierConfig, User, UserSubscription, CONFIG, EMAIL_TO_ADDR, TIER_CONFIGS, TOTAL_USERS, USERS};

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("xion1pfpzqewmte52jf3lk9c6y4mldxtee7av47s59jpcn2utxfeya5uqylukh4"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            burnt_wallet_api_key: "dummy_key".to_string(),
            treasury_admin: Some("xion1pfpzqewmte52jf3lk9c6y4mldxtee7av47s59jpcn2utxfeya5uqylukh4".to_string()),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(res.attributes.len(), 4);
        assert_eq!(res.attributes[0], attr("action", "instantiate"));
        assert_eq!(res.attributes[1].key, "timestamp_seconds");
        assert_eq!(res.attributes[2].key, "formatted_timestamp");
        assert_eq!(res.attributes[3], attr("user", "xion1pfpzqewmte52jf3lk9c6y4mldxtee7av47s59jpcn2utxfeya5uqylukh4"));

        let config: Config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.admin(), Addr::unchecked("xion1pfpzqewmte52jf3lk9c6y4mldxtee7av47s59jpcn2utxfeya5uqylukh4"));
        assert_eq!(config.burnt_wallet_api_key(), "qwer1234321234erwqwer");
        assert_eq!(config.treasury_admin(), Addr::unchecked("xionTREASURYQwdeo1294ncwjdicwe823bjcwd"));

        let total_users: u64 = TOTAL_USERS.load(&deps.storage).unwrap();
        assert_eq!(total_users, 0);

        let free_tier: TierConfig = TIER_CONFIGS
            .load(&deps.storage, &tier_to_key(&SubscriptionTier::Free))
            .unwrap();
        assert_eq!(free_tier.price(), Uint128::zero());
        assert_eq!(free_tier.cv_limit(), 0);
        assert_eq!(free_tier.treasury_address(), Addr::unchecked("xionTREASURYQwdeo1294ncwjdicwe823bjcwdhsdnerhtjduaksowjeurhdber"));
    }
}