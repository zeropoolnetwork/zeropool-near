use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::require;
use near_sdk::{env, near_bindgen, AccountId};

/// Minimal operator implementation
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RelayerPool {
    operator: AccountId,
}

impl Default for RelayerPool {
    fn default() -> Self {
        Self {
            operator: env::current_account_id(),
        }
    }
}

#[near_bindgen]
impl RelayerPool {
    #[init]
    pub fn new() -> Self {
        RelayerPool { operator: env::current_account_id() }
    }

    #[private]
    pub fn set_operator(&mut self, operator: AccountId) {
        self.operator = operator;
    }

    pub fn operator(&self) -> AccountId {
        self.operator.clone()
    }
}
