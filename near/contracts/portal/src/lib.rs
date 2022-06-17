//#![allow(unused_mut)]
//#![allow(unused_imports)]
//#![allow(unused_variables)]
//#![allow(dead_code)]

use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadata, FT_METADATA_SPEC};
use near_sdk::json_types::{Base64VecU8, U128};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::{
    env, ext_contract, near_bindgen, require, AccountId, Balance, Gas, PanicOnDefault, Promise,
    PromiseError, PromiseOrValue, PublicKey,
};
use serde::{Deserialize, Serialize};

use near_sdk::utils::is_promise_success;

use near_sys as sys;

use std::str;

pub mod byte_utils;
pub mod state;

use crate::byte_utils::{get_string_from_32, ByteUtils};

// near_sdk::setup_alloc!();

const CHAIN_ID_NEAR: u16 = 15;
const CHAIN_ID_SOL: u16 = 1;

const BRIDGE_TOKEN_BINARY: &[u8] =
    include_bytes!("../../ft/target/wasm32-unknown-unknown/release/ft.wasm");

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 20_000_000_000_000_000_000_000;

/// Gas to initialize BridgeToken contract.
//const BRIDGE_TOKEN_NEW: Gas = Gas(100_000_000_000_000);

/// Gas to call mint method on bridge token.
//const MINT_GAS: Gas = Gas(10_000_000_000_000);

#[ext_contract(ext_ft_contract)]
pub trait FtContract {
    fn new(metadata: FungibleTokenMetadata, asset_meta: Vec<u8>, seq_number: u64) -> Self;
    fn update_ft(metadata: FungibleTokenMetadata, asset_meta: Vec<u8>, seq_number: u64);
    fn ft_transfer_call(
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
    fn ft_metadata(&self) -> FungibleTokenMetadata;
    fn vaa_transfer(
        &self,
        amount: u128,
        token_address: Vec<u8>,
        token_chain: u16,
        recipient: Vec<u8>,
        recipient_chain: u16,
        fee: u128,
    );
    fn vaa_withdraw(
        &self,
        from: AccountId,
        amount: u128,
        receiver: String,
        chain: u16,
        fee: u128,
        payload: String,
    ) -> String;
}

#[ext_contract(ext_worm_hole)]
pub trait Wormhole {
    fn verify_vaa(&self, vaa: String) -> u32;
    fn publish_message(&self, data: String, nonce: u32) -> u64;
}

#[ext_contract(ext_portal)]
pub trait ExtPortal {
    fn finish_deploy(&self, tkey: Vec<u8>, token: String);
    fn vaa_transfer_complete(&self);
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct TransferMsgPayload {
    receiver: String,
    chain: u16,
    fee: u128,
    payload: String,
}

#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct TokenData {
    meta: Vec<u8>,
    account: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Portal {
    booted: bool,
    core: AccountId,
    dups: UnorderedSet<Vec<u8>>,
    good: UnorderedSet<Vec<u8>>,
    owner_pk: PublicKey,
    emitter_registration: LookupMap<u16, Vec<u8>>,
    tokens: LookupMap<Vec<u8>, TokenData>,
    token_map: LookupMap<u32, Vec<u8>>,
    last_asset: u32,
    upgrade_hash: Vec<u8>,
}

impl Default for Portal {
    fn default() -> Self {
        Self {
            booted: false,
            core: AccountId::new_unchecked("".to_string()),
            dups: UnorderedSet::new(b"d".to_vec()),
            good: UnorderedSet::new(b"g".to_vec()),
            owner_pk: env::signer_account_pk(),
            emitter_registration: LookupMap::new(b"c".to_vec()),
            tokens: LookupMap::new(b"t".to_vec()),
            token_map: LookupMap::new(b"m".to_vec()),
            last_asset: 0,
            upgrade_hash: b"".to_vec(),
        }
    }
}

fn vaa_register_chain(storage: &mut Portal, vaa: state::ParsedVAA) {
    let data: &[u8] = &vaa.payload;
    let target_chain = data.get_u16(33);
    let chain = data.get_u16(35);

    if (target_chain != CHAIN_ID_NEAR) && (target_chain != 0) {
        env::panic_str("InvalidRegisterChainChain");
    }

    if storage.emitter_registration.contains_key(&chain) {
        env::panic_str("DuplicateChainRegistration");
    }

    storage
        .emitter_registration
        .insert(&chain, &data[37..69].to_vec());

    env::log_str(&format!(
        "register chain {} to {}",
        chain,
        hex::encode(&data[37..69])
    ));
}

fn vaa_upgrade_contract(storage: &mut Portal, vaa: state::ParsedVAA) {
    let data: &[u8] = &vaa.payload;
    let chain = data.get_u16(33);
    if chain != CHAIN_ID_NEAR {
        env::panic_str("InvalidContractUpgradeChain");
    }

    let uh = data.get_bytes32(0);
    env::log_str(&format!(
        "portal/{}#{}: vaa_update_contract: {}",
        file!(),
        line!(),
        hex::encode(&uh)
    ));
    storage.upgrade_hash = uh.to_vec();
}

fn vaa_governance(storage: &mut Portal, vaa: state::ParsedVAA, gov_idx: u32) {
    if gov_idx != vaa.guardian_set_index {
        env::panic_str("InvalidGovernanceSet");
    }

    if (CHAIN_ID_SOL != vaa.emitter_chain)
        || (hex::decode("0000000000000000000000000000000000000000000000000000000000000004")
            .unwrap()
            != vaa.emitter_address)
    {
        env::panic_str("InvalidGovernanceEmitter");
    }

    let data: &[u8] = &vaa.payload;
    let action = data.get_u8(32);

    match action {
        1u8 => vaa_register_chain(storage, vaa),
        2u8 => vaa_upgrade_contract(storage, vaa),
        _ => env::panic_str("InvalidGovernanceAction"),
    }
}

fn vaa_transfer(storage: &mut Portal, vaa: state::ParsedVAA) -> Promise {
    env::log_str(&hex::encode(&vaa.payload));

    let data: &[u8] = &vaa.payload[1..];

    let tkey = data[32..66].to_vec();

    let amount = data.get_u256(0);
    let token_address = data.get_bytes32(32).to_vec();
    let token_chain = data.get_u16(64);
    let recipient = data.get_bytes32(66).to_vec();
    let recipient_chain = data.get_u16(98);
    let fee = data.get_u256(100);

    if recipient_chain != CHAIN_ID_NEAR {
        env::panic_str("InvalidRecipientChain");
    }

    if !storage.tokens.contains_key(&tkey) {
        env::panic_str("AssetNotAttested");
    }

    let bridge_token_account = storage.tokens.get(&tkey).unwrap().account;

    env::log_str(&bridge_token_account);

    if !env::is_valid_account_id(bridge_token_account.as_bytes()) {
        env::panic_str("InvalidAccountId");
    }

    if !storage.tokens.contains_key(&tkey) {
        env::panic_str("AssetNotAttested");
    }

    let bridge_token_account_id: AccountId = AccountId::new_unchecked(bridge_token_account);

    ext_ft_contract::ext(bridge_token_account_id)
        .with_attached_deposit(BRIDGE_TOKEN_INIT_BALANCE)
        .vaa_transfer(
            amount.1,
            token_address,
            token_chain,
            recipient,
            recipient_chain,
            fee.0,
        )
        .then(ext_portal::ext(env::current_account_id()).vaa_transfer_complete())
}

fn vaa_asset_meta(storage: &mut Portal, vaa: state::ParsedVAA) -> Promise {
    env::log_str(&format!("portal/{}#{}: vaa_asset_meta", file!(), line!()));

    env::log_str(&hex::encode(&vaa.payload));

    let data: &[u8] = &vaa.payload[1..];

    let tkey = data[0..34].to_vec();
    let token_chain = data.get_u16(32);

    if token_chain == CHAIN_ID_NEAR {
        env::panic_str("CannotAttestNearAssets");
    }

    let fresh;

    let bridge_token_account;

    if storage.tokens.contains_key(&tkey) {
        bridge_token_account = storage.tokens.get(&tkey).unwrap().account;
        fresh = false;
    } else {
        storage.last_asset += 1;
        let asset_id = storage.last_asset;
        bridge_token_account = format!("{}.{}", asset_id, env::current_account_id());

        let d = TokenData {
            meta: data.to_vec(),
            account: bridge_token_account.clone(),
        };
        storage.tokens.insert(&tkey, &d);
        storage.token_map.insert(&asset_id, &tkey);
        fresh = true;
    }

    env::log_str(&bridge_token_account);

    if !env::is_valid_account_id(bridge_token_account.as_bytes()) {
        env::panic_str("InvalidAccountId");
    }

    let bridge_token_account_id: AccountId = AccountId::new_unchecked(bridge_token_account.clone());

    // Stick some useful meta-data into the asset to allow us to map backwards from a on-chain asset to the wormhole meta data
    let reference = hex::encode(&tkey);
    let ref_hash = env::sha256(reference.as_bytes());

    let mut decimals = data.get_u8(34);
    let symbol = data.get_bytes32(35).to_vec();
    let name = data.get_bytes32(67).to_vec();
    let wname = get_string_from_32(&name) + " (Wormhole)";

    // Decimals are capped at 8 in wormhole
    if decimals > 8 {
        decimals = 8;
    }

    let ft = FungibleTokenMetadata {
        spec: FT_METADATA_SPEC.to_string(),
        name: wname,
        symbol: get_string_from_32(&symbol),
        icon: Some("".to_string()), // Is there ANY way to supply this?
        reference: Some(reference),
        reference_hash: Some(Base64VecU8::from(ref_hash)),
        decimals,
    };

    if !fresh {
        env::log_str(&format!("portal/{}#{}: vaa_asset_meta", file!(), line!()));
        ext_ft_contract::ext(bridge_token_account_id).update_ft(ft, data.to_vec(), vaa.sequence)
    } else {
        env::log_str(&format!("portal/{}#{}: vaa_asset_meta", file!(), line!()));
        let v = BRIDGE_TOKEN_BINARY.to_vec();

        if env::attached_deposit()
            < BRIDGE_TOKEN_INIT_BALANCE + (v.len() as u128 * env::storage_byte_cost())
        {
            env::panic_str("Not enough attached deposit to complete bridge token creation");
        }

        Promise::new(bridge_token_account_id.clone())
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE + (v.len() as u128 * env::storage_byte_cost()))
            .add_full_access_key(storage.owner_pk.clone())
            .deploy_contract(v)
            // Lets initialize it with useful stuff
            .then(ext_ft_contract::ext(bridge_token_account_id).new(
                ft,
                data.to_vec(),
                vaa.sequence,
            ))
            // And then lets tell us we are done!
            .then(
                ext_portal::ext(env::current_account_id())
                    .finish_deploy(tkey, bridge_token_account),
            )
    }
}

pub fn submit_vaa_callback_work(storage: &mut Portal, vaa: String, gov_idx: u32) -> Promise {
    //    env::log_str(&"submit_vaa_callback_work::top");

    let h = hex::decode(vaa).expect("invalidVaa");

    let pvaa = state::ParsedVAA::parse(&h);

    if pvaa.version != 1 {
        env::panic_str("InvalidVersion");
    }

    let data: &[u8] = &pvaa.payload;

    let governance = data[0..32]
        == hex::decode("000000000000000000000000000000000000000000546f6b656e427269646765").unwrap();
    let action = data.get_u8(0);

    if !governance && action == 2u8 {
        if storage.good.contains(&pvaa.hash) {
            //            env::log_str(&"submit_vaa_callback_work::remove");
            storage.good.remove(&pvaa.hash);
        } else {
            //            env::log_str(&"submit_vaa_callback_work::insert and return");
            storage.good.insert(&pvaa.hash);
            return Promise::new(env::signer_account_id());
        }
    }

    //    env::log_str(&"submit_vaa_callback_work::getting_work_done");

    // Check if VAA with this hash was already accepted
    if storage.dups.contains(&pvaa.hash) {
        env::panic_str("alreadyExecuted");
    }
    storage.dups.insert(&pvaa.hash);

    if governance {
        vaa_governance(storage, pvaa, gov_idx);
        return Promise::new(env::signer_account_id());
    }

    //    env::log_str(&format!("looking up chain {}", pvaa.emitter_chain));

    if !storage
        .emitter_registration
        .contains_key(&pvaa.emitter_chain)
    {
        env::panic_str("ChainNotRegistered");
    }

    if storage
        .emitter_registration
        .get(&pvaa.emitter_chain)
        .unwrap()
        != pvaa.emitter_address
    {
        env::panic_str("InvalidRegistration");
    }

    //    env::log_str(&"submit_vaa_callback_work::branching_to_actions");

    match action {
        1u8 => vaa_transfer(storage, pvaa),
        2u8 => vaa_asset_meta(storage, pvaa),
        3u8 => vaa_transfer(storage, pvaa),
        _ => {
            env::panic_str("InvalidPortalAction");
        }
    }
}

#[near_bindgen]
impl Portal {
    #[private]
    pub fn emitter_callback(&mut self, #[callback_result] seq: Result<u64, PromiseError>) -> u64 {
        env::log_str(&format!(
            "portal/{}#{}: used_gas: {} prepaid_gas: {}",
            file!(),
            line!(),
            serde_json::to_string(&env::used_gas()).unwrap(),
            serde_json::to_string(&env::prepaid_gas()).unwrap()
        ));

        if seq.is_err() {
            env::panic_str("EmitFail");
        }

        seq.unwrap()
    }

    #[payable]
    pub fn send_transfer_near(
        &mut self,
        receiver: String,
        chain: u16,
        fee: u128,
        payload: String,
    ) -> Promise {
        require!(
            env::prepaid_gas() >= Gas(100_000_000_000_000),
            &format!(
                "portal/{}#{}: more gas is required {}",
                file!(),
                line!(),
                serde_json::to_string(&env::prepaid_gas()).unwrap()
            )
        );

        let amount = env::attached_deposit();
        if amount == 0 {
            env::panic_str("level up your game");
        }

        const NEAR_MULT: u128 = 10_000_000_000_000_000; // 1e16

        let namount = amount / NEAR_MULT;
        let nfee = fee / NEAR_MULT;
        //let dust = amount - (namount * NEAR_MULT) - (nfee * NEAR_MULT);

        let mut p = [
            // PayloadID uint8 = 1
            (if payload.is_empty() { 1 } else { 3 } as u8)
                .to_be_bytes()
                .to_vec(),
            // Amount uint256
            vec![0; 24],
            (namount as u64).to_be_bytes().to_vec(),
            //TokenAddress bytes32
            vec![0; 32],
            // TokenChain uint16
            (CHAIN_ID_NEAR as u16).to_be_bytes().to_vec(),
            // To bytes32
            vec![0; (64 - receiver.len()) / 2],
            hex::decode(receiver).unwrap(),
            // ToChain uint16
            (chain as u16).to_be_bytes().to_vec(),
        ]
        .concat();

        if payload.is_empty() {
            p = [p, vec![0; 24], (nfee as u64).to_be_bytes().to_vec()].concat();
            if p.len() != 133 {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::predecessor_account_id()
                ));

                Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
                env::panic_str(&format!("paylod1 formatting errro  len = {}", p.len()));
            }
        } else {
            p = [p, hex::decode(&payload).unwrap()].concat();
            if p.len() != (133 + (payload.len() / 2)) {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::predecessor_account_id()
                ));

                Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
                env::panic_str(&format!("paylod3 formatting errro  len = {}", p.len()));
            }
        }

        ext_worm_hole::ext(self.core.clone())
            .publish_message(hex::encode(p), env::block_height() as u32)
            .then(Self::ext(env::current_account_id()).emitter_callback())
    }

    pub fn get_original_asset(&self, token: String) -> (u16, String) {
        let acct = env::current_account_id();
        let account = acct.as_str();

        let wh = &token[(token.len() - account.len())..];
        if wh != account {
            env::panic_str("OnlyWormholeAssets");
        }

        let a = &token[..(token.len() - account.len() - 1)];

        let asset_id = a.parse().unwrap();

        if !self.token_map.contains_key(&asset_id) {
            env::panic_str("UnknownAssetId");
        }

        let tref: &[u8] = &self.token_map.get(&asset_id).unwrap();

        (tref.get_u16(32), hex::encode(&tref[0..32]))
    }

    pub fn account_hash(&self) -> (String, String) {
        let acct = env::current_account_id();
        let astr = acct.to_string();

        (astr.clone(), hex::encode(env::sha256(astr.as_bytes())))
    }

    pub fn is_wormhole(&self, token: &String) -> bool {
        let astr = format!(".{}", env::current_account_id().as_str());
        token.ends_with(&astr)
    }

    pub fn get_foreign_asset(&self, chain: u16, asset_str: String) -> String {
        let asset = hex::decode(asset_str).unwrap();

        let p = [asset, chain.to_be_bytes().to_vec()].concat();

        if self.tokens.contains_key(&p) {
            return self.tokens.get(&p).unwrap().account;
        }

        "".to_string()
    }

    #[payable]
    pub fn register_account(&mut self, account: String) -> String {
        let astr = format!(".{}", env::current_account_id().as_str());
        if account.ends_with(&astr) {
            env::panic_str("CannotRegisterWormholeAccount");
        }

        let storage_used = env::storage_usage() as i128;

        let account_hash = env::sha256(&account.as_bytes());
        let ret = hex::encode(&account_hash);
        let p = [account_hash, CHAIN_ID_NEAR.to_be_bytes().to_vec()].concat();
        if !self.tokens.contains_key(&p) {
            let d = TokenData {
                meta: b"".to_vec(),
                account: account,
            };
            self.tokens.insert(&p, &d);
        }

        let delta =
            (env::storage_usage() as i128 - storage_used) * env::storage_byte_cost() as i128;

        let refund = env::attached_deposit() as i128 - delta;
        if refund < 0 {
            env::panic_str("InvalidStorageDeposit");
        }
        if refund > 0 {
            env::log_str(&format!(
                "portal/{}#{}: update_contract_done: refund {} to {}",
                file!(),
                line!(),
                refund,
                env::predecessor_account_id()
            ));
            Promise::new(env::predecessor_account_id()).transfer(refund as u128);
        }

        ret
    }

    pub fn lookup_account_hash(&self, account: String) -> (bool, String) {
        let account_hash = env::sha256(&account.as_bytes());
        let ret = hex::encode(&account_hash);
        let p = [account_hash, CHAIN_ID_NEAR.to_be_bytes().to_vec()].concat();
        if !self.tokens.contains_key(&p) {
            (false, ret)
        } else {
            (true, ret)
        }
    }

    pub fn send_transfer_wormhole_token(
        &self,
        amount: u128,
        token: String,
        receiver: String,
        chain: u16,
        fee: u128,
        payload: String,
    ) -> Promise {
        if self.is_wormhole(&token) {
            ext_ft_contract::ext(AccountId::try_from(token).unwrap())
                .vaa_withdraw(
                    env::predecessor_account_id(),
                    amount,
                    receiver,
                    chain,
                    fee,
                    payload,
                )
                .then(Self::ext(env::current_account_id()).send_transfer_token_wormhole_callback())
        } else {
            env::panic_str("NotWormhole");
        }
    }

    #[private]
    pub fn send_transfer_token_wormhole_callback(
        &self,
        #[callback_result] payload: Result<String, PromiseError>,
    ) -> Promise {
        if payload.is_err() {
            env::panic_str("PayloadError");
        }

        // Failing here would suck chunks...  The money has already
        // been burned from the account so we better succeed...

        ext_worm_hole::ext(self.core.clone())
            .publish_message(payload.unwrap(), env::block_height() as u32)
            .then(Self::ext(env::current_account_id()).emitter_callback())
    }

    pub fn is_transfer_completed(&self, vaa: String) -> bool {
        let h = hex::decode(vaa).expect("invalidVaa");
        let pvaa = state::ParsedVAA::parse(&h);

        self.dups.contains(&pvaa.hash)
    }

    #[payable]
    pub fn submit_vaa(&mut self, vaa: String) -> Promise {
        //        env::log_str(&"submit_vaa::start");
        let h = hex::decode(&vaa).expect("invalidVaa");

        // Please optimize this next time you are bored and just have it do the hash calculation...
        let pvaa = state::ParsedVAA::parse(&h);

        if self.good.contains(&pvaa.hash) {
            submit_vaa_callback_work(self, vaa, 0)
        } else {
            ext_worm_hole::ext(self.core.clone())
                .verify_vaa(vaa.clone())
                .then(Self::ext(env::current_account_id()).submit_vaa_callback(vaa))
        }
    }

    pub fn attest_near(&mut self) -> Promise {
        require!(
            env::prepaid_gas() >= Gas(100_000_000_000_000),
            &format!(
                "portal/{}#{}: more gas is required {}",
                file!(),
                line!(),
                serde_json::to_string(&env::prepaid_gas()).unwrap()
            )
        );

        let p = [
            (2_u8).to_be_bytes().to_vec(),
            vec![0; 32],
            (CHAIN_ID_NEAR as u16).to_be_bytes().to_vec(),
            (24_u8).to_be_bytes().to_vec(), // yectoNEAR is 1e24 ...
            byte_utils::extend_string_to_32("NEAR"),
            byte_utils::extend_string_to_32("NEAR"),
        ]
        .concat();

        if p.len() != 100 {
            env::log_str(&format!("len: {}  val: {}", p.len(), hex::encode(p)));
            env::panic_str("Formatting error");
        }

        ext_worm_hole::ext(self.core.clone())
            .publish_message(hex::encode(p), env::block_height() as u32)
            .then(Self::ext(env::current_account_id()).emitter_callback())
    }

    pub fn attest_token(&mut self, token: String) -> Promise {
        require!(
            env::prepaid_gas() >= Gas(100_000_000_000_000),
            &format!(
                "portal/{}#{}: more gas is required {}",
                file!(),
                line!(),
                serde_json::to_string(&env::prepaid_gas()).unwrap()
            )
        );

        env::log_str(&format!(
            "portal/{}#{}: used_gas: {} prepaid_gas: {}",
            file!(),
            line!(),
            serde_json::to_string(&env::used_gas()).unwrap(),
            serde_json::to_string(&env::prepaid_gas()).unwrap()
        ));

        if self.is_wormhole(&token) {
            let acct = env::current_account_id();
            let account = acct.as_str();
            let a = &token[..(token.len() - account.len() - 1)];

            let asset_id = a.parse().unwrap();

            if !self.token_map.contains_key(&asset_id) {
                env::panic_str("UnknownAssetId");
            }

            let tref = &self.token_map.get(&asset_id).unwrap();

            if !self.tokens.contains_key(&tref) {
                env::panic_str("InvalidWormholeToken");
            }
            let p = [
                (2_u8).to_be_bytes().to_vec(),
                self.tokens.get(&tref).unwrap().meta,
            ]
            .concat();
            if p.len() != 100 {
                env::log_str(&format!("len: {}  val: {}", p.len(), hex::encode(p)));
                env::panic_str("Formatting error");
            }
            ext_worm_hole::ext(self.core.clone())
                .publish_message(hex::encode(p), env::block_height() as u32)
                .then(Self::ext(env::current_account_id()).emitter_callback())
        } else {
            let account_hash = env::sha256(&token.as_bytes());
            let tref = [account_hash, CHAIN_ID_NEAR.to_be_bytes().to_vec()].concat();
            if !self.tokens.contains_key(&tref) {
                env::panic_str("UnregisteredNativeToken");
            }

            ext_ft_contract::ext(AccountId::try_from(token.clone()).unwrap())
                .with_static_gas(Gas(10_000_000_000_000))
                .ft_metadata()
                .then(Self::ext(env::current_account_id()).attest_token_callback(token))
        }
    }

    #[private]
    pub fn attest_token_callback(
        &mut self,
        token: String,
        #[callback_result] ft_info: Result<FungibleTokenMetadata, PromiseError>,
    ) -> Promise {
        env::log_str(&format!(
            "portal/{}#{}: used_gas: {}  prepaid_gas: {}",
            file!(),
            line!(),
            serde_json::to_string(&env::used_gas()).unwrap(),
            serde_json::to_string(&env::prepaid_gas()).unwrap()
        ));

        if ft_info.is_err() {
            env::panic_str("FailedToRetrieveMetaData");
        }

        let ft = ft_info.unwrap();

        let h = env::sha256(token.as_bytes());
        let p = [
            (2_u8).to_be_bytes().to_vec(),
            h,
            (CHAIN_ID_NEAR as u16).to_be_bytes().to_vec(),
            (ft.decimals as u8).to_be_bytes().to_vec(), // yectoNEAR is 1e24 ...
            byte_utils::extend_string_to_32(&ft.symbol),
            byte_utils::extend_string_to_32(&ft.name),
        ]
        .concat();

        if p.len() != 100 {
            env::log_str(&format!("len: {}  val: {}", p.len(), hex::encode(p)));
            env::panic_str("Formatting error");
        }

        env::log_str(&format!(
            "portal/{}#{}: used_gas: {} prepaid_gas: {}",
            file!(),
            line!(),
            serde_json::to_string(&env::used_gas()).unwrap(),
            serde_json::to_string(&env::prepaid_gas()).unwrap()
        ));

        ext_worm_hole::ext(self.core.clone())
            .publish_message(hex::encode(p), env::block_height() as u32)
            .then(Self::ext(env::current_account_id()).emitter_callback())
    }

    #[private]
    pub fn vaa_transfer_complete(&mut self) {
        if !is_promise_success() {
            env::log_str("is_promise_success() = false");
            unsafe {
                sys::panic();
            }
        } else {
            env::log_str("is_promise_success() = true");
        }
    }

    #[private]
    pub fn finish_deploy(&mut self, tkey: Vec<u8>, token: String) -> String {
        if is_promise_success() {
            env::log_str("We made it... what does that mean?");
            env::log_str(&hex::encode(&tkey));
            token
        } else {
            env::panic_str("bad deploy");
        }
    }

    #[private] // So, all of wormhole security rests in this one statement?
    pub fn submit_vaa_callback(
        &mut self,
        vaa: String,
        #[callback_result] gov_idx: Result<u32, PromiseError>,
    ) {
        // Is this even needed anymore?
        if (env::promise_results_count() != 1)
            || (env::predecessor_account_id() != env::current_account_id())
        {
            env::panic_str("BadPredecessorAccount");
        }

        // Is there anyway to confirm the person I called and is
        // calling me back here is the person is the core_contract?

        if gov_idx.is_err() {
            env::panic_str("vaaVerifyFail");
        }

        submit_vaa_callback_work(self, vaa, gov_idx.unwrap()).as_return();
    }

    #[private]
    pub fn ft_on_transfer_callback(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
        token: AccountId,
        #[callback_result] ft_info: Result<FungibleTokenMetadata, PromiseError>,
    ) -> PromiseOrValue<U128> {
        env::log_str(&format!(
            "portal/{}#{}: ft_on_transfer_callback",
            file!(),
            line!()
        ));

        if ft_info.is_err() {
            env::panic_str("ft_infoError");
        }

        if env::signer_account_id() != sender_id {
            env::panic_str("signer != sender");
        }

        let ft = ft_info.unwrap();
        let tp: TransferMsgPayload = near_sdk::serde_json::from_str(&msg).unwrap();

        let mut near_mult: u128 = 1;

        if ft.decimals > 8 {
            near_mult = 10_u128.pow(ft.decimals as u32 - 8);
        }

        env::log_str(&format!(
            "portal/{}#{}: ft_on_transfer_callback:  near_mult: {}",
            file!(),
            line!(),
            near_mult
        ));

        let namount = u128::from(amount) / near_mult;
        let nfee = tp.fee / near_mult;

        if namount == 0 {
            if env::attached_deposit() != 0 {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::signer_account_id()
                ));

                Promise::new(env::signer_account_id()).transfer(env::attached_deposit());
            }
            env::panic_str("EmptyTransfer");
        }

        let mut p = [
            // PayloadID uint8 = 1
            (if tp.payload.is_empty() { 1 } else { 3 } as u8)
                .to_be_bytes()
                .to_vec(),
            // Amount uint256
            vec![0; 24],
            (namount as u64).to_be_bytes().to_vec(),
            //TokenAddress bytes32
            env::sha256(token.to_string().as_bytes()),
            // TokenChain uint16
            (CHAIN_ID_NEAR as u16).to_be_bytes().to_vec(),
            // To bytes32
            vec![0; (64 - tp.receiver.len()) / 2],
            hex::decode(tp.receiver).unwrap(),
            // ToChain uint16
            (tp.chain as u16).to_be_bytes().to_vec(),
        ]
        .concat();

        if tp.payload.is_empty() {
            p = [p, vec![0; 24], (nfee as u64).to_be_bytes().to_vec()].concat();
            if p.len() != 133 {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::predecessor_account_id()
                ));

                Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
                env::panic_str(&format!("paylod1 formatting errro  len = {}", p.len()));
            }
        } else {
            p = [p, hex::decode(&tp.payload).unwrap()].concat();
            if p.len() != (133 + (tp.payload.len() / 2)) {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::predecessor_account_id()
                ));

                Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
                env::panic_str(&format!("paylod3 formatting errro  len = {}", p.len()));
            }
        }

        env::log_str(&format!("{}: ft_on_transfer_callback", line!()));

        PromiseOrValue::Promise(
            ext_worm_hole::ext(self.core.clone())
                .publish_message(hex::encode(p), env::block_height() as u32)
                .then(Self::ext(env::current_account_id()).emitter_callback_pov()),
        )
    }

    #[private]
    pub fn emitter_callback_pov(
        &mut self,
        #[callback_result] seq: Result<u64, PromiseError>,
    ) -> PromiseOrValue<U128> {
        env::log_str(&format!("{}: emitter_callback_pov", line!()));

        if seq.is_err() {
            env::panic_str("EmitFail");
        }

        PromiseOrValue::Value(U128::from(0))
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        // Where did my 1 attached_deposit go?!
        //        env::log_str(&format!("portal/{}#{}: ft_on_transfer", file!(), line!()));
        //        assert_one_yocto();
        env::log_str(&format!(
            "portal/{}#{}: ft_on_transfer attached_deposit:  {}",
            file!(),
            line!(),
            env::attached_deposit()
        ));

        // require!(env::prepaid_gas() >= GAS_FOR_FT_TRANSFER_CALL, "More gas is required");

        PromiseOrValue::Promise(
            ext_ft_contract::ext(env::predecessor_account_id())
                .ft_metadata()
                .then(
                    Self::ext(env::current_account_id()).ft_on_transfer_callback(
                        sender_id,
                        amount,
                        msg,
                        env::predecessor_account_id(),
                    ),
                ),
        )
    }

    pub fn boot_portal(&mut self, core: String) {
        if self.owner_pk != env::signer_account_pk() {
            env::panic_str("invalidSigner");
        }

        if self.booted {
            env::panic_str("NoDonut");
        }
        self.booted = true;
        self.core = AccountId::try_from(core).unwrap();

        env::log_str(&format!(
            "portal emitter: {}",
            hex::encode(env::sha256(
                env::current_account_id().to_string().as_bytes()
            ))
        ));
    }

    #[private]
    pub fn update_contract_done(
        &mut self,
        refund_to: near_sdk::AccountId,
        storage_used: u64,
        attached_deposit: u128,
    ) {
        let delta = (env::storage_usage() as i128 - storage_used as i128)
            * env::storage_byte_cost() as i128;
        let refund = attached_deposit as i128 - delta;
        if refund > 0 {
            env::log_str(&format!(
                "portal/{}#{}: update_contract_done: refund {} to {}",
                file!(),
                line!(),
                refund,
                refund_to
            ));
            Promise::new(refund_to).transfer(refund as u128);
        }
    }

    #[private]
    fn update_contract_work(&mut self, v: Vec<u8>) -> Promise {
        if env::attached_deposit() == 0 {
            env::panic_str("attach some cash");
        }

        let s = env::sha256(&v);

        env::log_str(&format!(
            "portal/{}#{}: update_contract: {}",
            file!(),
            line!(),
            hex::encode(&s)
        ));

        if s.to_vec() != self.upgrade_hash {
            if env::attached_deposit() > 0 {
                env::log_str(&format!(
                    "portal/{}#{}: refunding {} to {}",
                    file!(),
                    line!(),
                    env::attached_deposit(),
                    env::predecessor_account_id()
                ));

                Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
            }
            env::panic_str("invalidUpgradeContract");
        }

        Promise::new(env::current_account_id())
            .deploy_contract(v.to_vec())
            .then(Self::ext(env::current_account_id()).update_contract_done(
                env::predecessor_account_id(),
                env::storage_usage(),
                env::attached_deposit(),
            ))
    }
}

//  let result = await userAccount.functionCall({
//    contractId: config.tokenAccount,
//    methodName: "update_contract",
//    args: wormholeContract,
//    attachedDeposit: "12500000000000000000000",
//    gas: 300000000000000,
//  });

#[no_mangle]
pub extern "C" fn update_contract() {
    env::setup_panic_hook();
    let mut contract: Portal = env::state_read().expect("Contract is not initialized");
    contract.update_contract_work(env::input().unwrap());
}
