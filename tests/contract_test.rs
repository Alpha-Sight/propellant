#[cfg(test)]
mod tests {
    use propellant_Dapp::contract::instantiate;
    use propellant_Dapp::msg::InstantiateMsg;
    use propellant_Dapp::state::{tier_to_key, Config, SubscriptionTier, TierConfig, CONFIG, TIER_CONFIGS, TOTAL_USERS};

    use cosmwasm_std::testing::{mock_dependencies, mock_env, message_info};
    use cosmwasm_std::{attr, Addr, Uint128};

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("xionQwdeo1294ncwjdicwe823bjcwd"), &[]);
        let msg = InstantiateMsg {
            admin: None,
            burnt_wallet_api_key: "dummy_key".to_string(),
            treasury_admin: None,
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(res.attributes.len(), 4);
        assert_eq!(res.attributes[0], attr("action", "instantiate"));
        assert_eq!(res.attributes[1].key, "timestamp_seconds");
        assert_eq!(res.attributes[2].key, "formatted_timestamp");
        assert_eq!(res.attributes[3], attr("user", "xionQwdeo1294ncwjdicwe823bjcwd"));

        let config: Config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.admin(), Addr::unchecked("xionPRAISEQwdeo1294ncwjdicwe823bjcwd"));
        assert_eq!(config.burnt_wallet_api_key(), "qwer1234321234erwqwer");
        assert_eq!(config.treasury_admin(), Addr::unchecked("xionTREASURYQwdeo1294ncwjdicwe823bjcwd"));

        let total_users: u64 = TOTAL_USERS.load(&deps.storage).unwrap();
        assert_eq!(total_users, 0);

        let free_tier: TierConfig = TIER_CONFIGS
            .load(&deps.storage, &tier_to_key(&SubscriptionTier::Free))
            .unwrap();
        assert_eq!(free_tier.price(), Uint128::zero());
        assert_eq!(free_tier.cv_limit(), 0);
        assert_eq!(free_tier.treasury_address(), Addr::unchecked("xionQwdeo1294ncwjdicwe823bjcwd"));
    }
}