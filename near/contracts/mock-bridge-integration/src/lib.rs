#![allow(unused_variables)]

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

use near_sdk::json_types::{U128};
use near_sdk::{env, ext_contract, near_bindgen, AccountId, Balance, Promise, PromiseOrValue};

use near_sdk::utils::is_promise_success;

const BRIDGE_TOKEN_BINARY: &[u8] = include_bytes!(
    "../../mock-bridge-token/target/wasm32-unknown-unknown/release/moch_bridge_token.wasm"
);

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 5_860_000_000_000_000_000_000;

#[ext_contract(ext_ft_contract)]
pub trait MockFtContract {
    fn new() -> Self;
    fn airdrop(&self, a: AccountId, amount: u128);
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize,Default)]
pub struct PortalTest {}

#[near_bindgen]
impl PortalTest {
    #[payable]
    pub fn deploy_ft(&mut self, account: String) -> Promise {
        let a = AccountId::try_from(account).unwrap();

        let name = format!("b{}", env::block_height());

        let bridge_token_account = format!("{}.{}", name, env::current_account_id());

        let bridge_token_account_id: AccountId =
            AccountId::new_unchecked(bridge_token_account.clone());

        let v = BRIDGE_TOKEN_BINARY.to_vec();

        Promise::new(bridge_token_account_id.clone())
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE + (v.len() as u128 * env::storage_byte_cost()))
            .add_full_access_key(env::signer_account_pk())
            .deploy_contract(v)
            // Lets initialize it with useful stuff
            .then(ext_ft_contract::ext(bridge_token_account_id.clone()).new())
            .then(ext_ft_contract::ext(bridge_token_account_id)
                  .with_attached_deposit(BRIDGE_TOKEN_INIT_BALANCE)
                  .airdrop(a, BRIDGE_TOKEN_INIT_BALANCE))
            // And then lets tell us we are done!
            .then(Self::ext(env::current_account_id()).finish_deploy(bridge_token_account))
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        env::log_str(&msg);
        env::panic_str("ft_on_transfer");
    }

    #[private]
    pub fn finish_deploy(&mut self, ret: String) -> String {
        if is_promise_success() {
            ret
        } else {
            env::panic_str("bad deploy");
        }
    }
}
