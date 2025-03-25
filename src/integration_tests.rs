#[cfg(test)]
mod integration_tests {
    use cosmwasm_std::{Addr, Empty, StdResult, StdError, Uint128, Coin};
    use cw_multi_test::{App, Contract, ContractWrapper, Executor};
    
    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, TotalUsersResponse};
    use crate::contract::{execute, instantiate, query};
    use crate::state::SubscriptionTier;
    
    // Create a wrapper for your contract
    fn cv_generator_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(execute, instantiate, query);
        Box::new(contract)
    }
    
    // Helper struct to interact with your contract in tests
    struct CvGeneratorContract(Addr);
    
    impl CvGeneratorContract {
        // Function to call execute messages - fixed Vec<Coin> parameter type
        fn execute(&self, app: &mut App, sender: &str, msg: ExecuteMsg, funds: Option<Vec<Coin>>) -> StdResult<()> {
            let coins = funds.unwrap_or_default();
            app.execute_contract(Addr::unchecked(sender), self.0.clone(), &msg, &coins)
                .map(|_| ())
                .map_err(|err| StdError::generic_err(err.to_string()))
        }
        
        // Function to call query messages
        fn query<T: serde::de::DeserializeOwned>(&self, app: &App, msg: QueryMsg) -> T {
            app.wrap().query_wasm_smart(self.0.clone(), &msg).unwrap()
        }
        
        // Helper to query total users
        fn query_total_users(&self, app: &App) -> u64 {
            let total_users: TotalUsersResponse = self.query(app, QueryMsg::GetTotalUsers {});
            total_users.total_users
        }
    }
    
    #[test]
    fn test_user_registration_and_subscription() {
        // Current timestamp: 2025-03-20 10:41:53
        // Login name: praiseunite
        
        // Test addresses
        const USER_ADDR: &str = "user1";
        const ADMIN: &str = "admin";
        const TREASURY: &str = "treasury";
        const USER_NAME: &str = "praiseunite";
        const USER_EMAIL: &str = "praiseunite@gmail.com";
        
        // Create a simulated blockchain with initial balances
        let mut app = App::new(|router, _api, storage| {
            router
                .bank
                .init_balance(
                    storage, 
                    &Addr::unchecked(USER_ADDR), 
                    vec![cosmwasm_std::coin(10000, "uxion")]
                )
                .unwrap();
        });
        
        // Store the contract code
        let code_id = app.store_code(cv_generator_contract());
        
        // Instantiate your contract
        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked(ADMIN),
                &InstantiateMsg {
                    admin: None,
                    burnt_wallet_api_key: "test_api_key".to_string(),
                    treasury_admin: None,
                },
                &[],
                "CV Generator",
                None,
            )
            .unwrap();
        
        let contract = CvGeneratorContract(contract_addr);
        
        // Configure the Basic tier
        contract
            .execute(
                &mut app,
                ADMIN,
                ExecuteMsg::ConfigureTier {
                    tier: SubscriptionTier::Basic,
                    price: Uint128::new(1500),
                    cv_limit: 1,
                    treasury_address: TREASURY.to_string(),
                },
                None,
            )
            .unwrap();
        
        // Register a user with your name (praiseunite)
        contract
            .execute(
                &mut app,
                USER_ADDR,
                ExecuteMsg::RegisterUser {
                    email: USER_EMAIL.to_string(),
                    name: Some(USER_NAME.to_string()),
                },
                None,
            )
            .unwrap();
        
        // Subscribe to Basic tier
        contract
            .execute(
                &mut app,
                USER_ADDR,
                ExecuteMsg::Subscribe {
                    tier: SubscriptionTier::Basic,
                },
                Some(vec![cosmwasm_std::coin(1500, "uxion")]),
            )
            .unwrap();
        
        // Verify total users
        let total_users = contract.query_total_users(&app);
        assert_eq!(total_users, 1);
        
        // Verify treasury received payment
        let treasury_balance = app
            .wrap()
            .query_balance(TREASURY.to_string(), "uxion")
            .unwrap();
        assert_eq!(treasury_balance.amount, Uint128::new(1500));
        
        println!("✅ User '{}' registered and subscribed to Basic tier!", USER_NAME);
        println!("✅ Treasury received {} uxion payment", treasury_balance.amount);
        println!("✅ Test completed at: 2025-03-20 10:41:53");
    }
    
    #[test]
    fn test_multiple_subscription_tiers() {
        // Create test environment with multiple users
        let mut app = App::new(|router, _api, storage| {
            // Initialize multiple users with funds
            for user in ["user1", "user2", "user3"] {
                router
                    .bank
                    .init_balance(
                        storage,
                        &Addr::unchecked(user),
                        vec![cosmwasm_std::coin(20000, "uxion")]
                    )
                    .unwrap();
            }
        });
        
        // Store and instantiate contract
        let code_id = app.store_code(cv_generator_contract());
        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("admin"),
                &InstantiateMsg {
                    admin: None,
                    burnt_wallet_api_key: "test_api_key".to_string(),
                    treasury_admin: None,
                },
                &[],
                "CV Generator with Multiple Tiers",
                None,
            )
            .unwrap();
            
        let contract = CvGeneratorContract(contract_addr);
        
        // Configure all tiers
        let tiers = [
            (SubscriptionTier::Basic, 1500u128, 1u32),
            (SubscriptionTier::Standard, 5000u128, 5u32),
            (SubscriptionTier::Premium, 10000u128, 15u32),
        ];
        
        for (tier, price, cv_limit) in tiers {
            contract
                .execute(
                    &mut app,
                    "admin",
                    ExecuteMsg::ConfigureTier {
                        tier,
                        price: Uint128::new(price),
                        cv_limit,
                        treasury_address: "treasury".to_string(),
                    },
                    None,
                )
                .unwrap();
        }
        
        // Register users to different tiers
        let users = [
            ("user1", "praiseunite@basic.com", SubscriptionTier::Basic, 1500u128),
            ("user2", "praiseunite@standard.com", SubscriptionTier::Standard, 5000u128),
            ("user3", "praiseunite@premium.com", SubscriptionTier::Premium, 10000u128),
        ];
        
        for (addr, email, tier, price) in users {
            // Register user
            contract
                .execute(
                    &mut app,
                    addr,
                    ExecuteMsg::RegisterUser {
                        email: email.to_string(),
                        name: Some("praiseunite".to_string()),
                    },
                    None,
                )
                .unwrap();
                
            // Subscribe to tier
            contract
                .execute(
                    &mut app,
                    addr,
                    ExecuteMsg::Subscribe {
                        tier,
                    },
                    Some(vec![cosmwasm_std::coin(price, "uxion")]),
                )
                .unwrap();
        }
        
        // Verify total users
        let total_users = contract.query_total_users(&app);
        assert_eq!(total_users, 3);
        
        // Verify treasury received all payments
        let treasury_balance = app
            .wrap()
            .query_balance("treasury".to_string(), "uxion")
            .unwrap();
        
        // Total should be sum of all tier prices: 1500 + 5000 + 10000 = 16500
        assert_eq!(treasury_balance.amount, Uint128::new(16500));
        
        println!("✅ Multiple users subscribed to different tiers");
        println!("✅ Treasury received total of {} uxion", treasury_balance.amount);
        println!("✅ Integration test by: praiseunite at 2025-03-20 10:41:53");
    }
}