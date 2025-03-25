pub mod contract;
pub mod error;
pub mod helpers;
pub mod msg;
pub mod state;
pub mod auth;



#[cfg(target_arch = "wasm32")]
mod backends {
    pub fn fill_inner(dest: &mut [u8]) -> Result<(), ()> {
        // Implementation for WASM target
        for byte in dest.iter_mut() {
            *byte = rand::random();
        }
        Ok(())
    }

    pub fn inner_u32() -> u32 {
        // Implementation for WASM target
        rand::random()
    }

    pub fn inner_u64() -> u64 {
        // Implementation for WASM target
        rand::random()
    }
}

#[cfg(target_arch = "wasm32")]
cosmwasm_std::create_entry_points!(crate::contract);