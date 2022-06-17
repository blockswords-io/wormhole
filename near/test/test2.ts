// npx pretty-quick

const sha256 = require("js-sha256");
const nearAPI = require("near-api-js");
const BN = require("bn.js");
const fs = require("fs").promises;
const assert = require("assert").strict;
const fetch = require("node-fetch");
const elliptic = require("elliptic");
const web3Utils = require("web3-utils");
import { zeroPad } from "@ethersproject/bytes";
import { NodeHttpTransport } from "@improbable-eng/grpc-web-node-http-transport";

import { TestLib } from "./testlib";

import {
  ChainId,
  CHAIN_ID_ALGORAND,
  CHAIN_ID_NEAR,
} from "@certusone/wormhole-sdk/lib/cjs/utils";

import { _parseVAAAlgorand } from "@certusone/wormhole-sdk/lib/cjs/algorand";

import { getSignedVAAWithRetry } from "@certusone/wormhole-sdk";

function getConfig(env: any) {
  switch (env) {
    case "sandbox":
    case "local":
      return {
        networkId: "sandbox",
        nodeUrl: "http://localhost:3030",
        masterAccount: "test.near",
        wormholeAccount:
          Math.floor(Math.random() * 10000).toString() + "wormhole.test.near",
        tokenAccount:
          Math.floor(Math.random() * 10000).toString() + "token.test.near",
        testAccount:
          Math.floor(Math.random() * 10000).toString() + "test.test.near",
        userAccount:
          Math.floor(Math.random() * 10000).toString() + "user.test.near",
      };
  }
}

const wormholeMethods = {
  viewMethods: [],
  changeMethods: ["boot_wormhole", "submit_vaa"],
};

const tokenMethods = {
  viewMethods: [],
  changeMethods: [
    "boot_portal",
    "submit_vaa",
    "submit_vaa_callback",
    "attest_near",
    "attest_token",
    "send_transfer_near",
    "send_transfer_wormhole_token",
    "account_hash",
  ],
};

const testMethods = {
  viewMethods: [],
  changeMethods: ["deploy_ft"],
};

const ftMethods = {
  viewMethods: [],
  changeMethods: ["ft_transfer_call", "storage_deposit"],
};

let config: any;
let masterAccount: any;
let _tokenAccount: any;
let _wormholeAccount: any;
let _testAccount: any;
let masterKey: any;
let masterPubKey: any;
let keyStore: any;
let near: any;

let userAccount: any;
let userKey: any;
let userPubKey: any;

async function initNear() {
  config = getConfig(process.env.NEAR_ENV || "sandbox");

  // Retrieve the validator key directly in the Tilt environment
  const response = await fetch("http://localhost:3031/validator_key.json");

  const keyFile = await response.json();

  console.log(keyFile);

  masterKey = nearAPI.utils.KeyPair.fromString(
    keyFile.secret_key || keyFile.private_key
  );
  masterPubKey = masterKey.getPublicKey();

  userKey = nearAPI.utils.KeyPair.fromRandom("ed25519");
  console.log(userKey);

  keyStore = new nearAPI.keyStores.InMemoryKeyStore();

  keyStore.setKey(config.networkId, config.masterAccount, masterKey);
  keyStore.setKey(config.networkId, config.userAccount, userKey);

  near = await nearAPI.connect({
    deps: {
      keyStore,
    },
    networkId: config.networkId,
    nodeUrl: config.nodeUrl,
  });
  masterAccount = new nearAPI.Account(near.connection, config.masterAccount);

  console.log(
    "Finish init NEAR masterAccount: " +
      JSON.stringify(await masterAccount.getAccountBalance())
  );

  let resp = await masterAccount.createAccount(
    config.userAccount,
    userKey.getPublicKey(),
    new BN(10).pow(new BN(25))
  );

  console.log(resp);

  userAccount = new nearAPI.Account(near.connection, config.userAccount);

  console.log(
    "Finish init NEAR userAccount: " +
      JSON.stringify(await userAccount.getAccountBalance())
  );

  //  console.log(await userAccount.sendMoney(config.masterAccount, nearAPI.utils.format.parseNearAmount("1.5")));;
  //  console.log("Sent some money: " + JSON.stringify(await userAccount.getAccountBalance()));
}

async function createContractUser(
  accountPrefix: any,
  contractAccountId: any,
  methods: any
) {
  let accountId =
    Math.floor(Math.random() * 10000).toString() +
    accountPrefix +
    "." +
    config.masterAccount;

  console.log(accountId);

  let randomKey = nearAPI.utils.KeyPair.fromRandom("ed25519");

  let resp = await masterAccount.createAccount(
    accountId,
    randomKey.getPublicKey(),
    new BN(10).pow(new BN(28))
  );
  console.log("accountId: " + JSON.stringify(resp));

  keyStore.setKey(config.networkId, accountId, randomKey);
  const account = new nearAPI.Account(near.connection, accountId);
  const accountUseContract = new nearAPI.Contract(
    account,
    contractAccountId,
    methods
  );
  return accountUseContract;
}

async function initTest() {
  const wormholeContract = await fs.readFile(
    "./contracts/wormhole/target/wasm32-unknown-unknown/release/wormhole.wasm"
  );
  const tokenContract = await fs.readFile(
    "./contracts/portal/target/wasm32-unknown-unknown/release/portal.wasm"
  );
  const testContract = await fs.readFile(
    "./contracts/mock-bridge-integration/target/wasm32-unknown-unknown/release/mock_bridge_integration.wasm"
  );

  let randomKey = nearAPI.utils.KeyPair.fromRandom("ed25519");
  keyStore.setKey(config.networkId, config.wormholeAccount, randomKey);

  _wormholeAccount = await masterAccount.createAndDeployContract(
    config.wormholeAccount,
    randomKey.getPublicKey(),
    wormholeContract,
    new BN(10).pow(new BN(27))
  );

  randomKey = nearAPI.utils.KeyPair.fromRandom("ed25519");
  keyStore.setKey(config.networkId, config.tokenAccount, randomKey);

  _tokenAccount = await masterAccount.createAndDeployContract(
    config.tokenAccount,
    randomKey.getPublicKey(),
    tokenContract,
    new BN(10).pow(new BN(27))
  );

  console.log("tokenAccount: " + config.tokenAccount);

  _testAccount = await masterAccount.createAndDeployContract(
    config.testAccount,
    randomKey.getPublicKey(),
    testContract,
    new BN(10).pow(new BN(27))
  );

  const wormholeUseContract = await createContractUser(
    "wormhole_user",
    config.wormholeAccount,
    wormholeMethods
  );

  console.log("Finish deploy contracts and create test accounts");
  return {
    wormholeUseContract,
  };
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nearParseResultForLogs(result: any): [number, string] {
  for (const o of result.receipts_outcome) {
    for (const l of o.outcome.logs) {
      console.log(l);
      if (l.startsWith("EVENT_JSON:")) {
        const body = JSON.parse(l.slice(11));
        if (body.standard == "wormhole" && body.event == "publish") {
          console.log(body);
          return [body.seq, body.emitter];
        }
      }
    }
  }
  return [-1, ""];
}

async function test() {
  let fastTest = true;
  let ts = new TestLib();

  await initNear();
  const { wormholeUseContract } = await initTest();

  console.log("Booting guardian set with index 0");

  console.log(ts.singleGuardianKey);

  await wormholeUseContract.boot_wormhole({
    args: { gset: 0, addresses: ts.singleGuardianKey },
  });
  console.log("Completed without an error... odd.. I am not sucking yet");

  let vaa =
    "01000000000100ea8654a8260d27ea4dc54d8b13892faa7a2a31ff0edb7b47360557c6a1303a1d144e6e94aa6b4bd20a98d36d46a3c66576893666731c6a866f300349f1c37f370162ac7102000000010008f5222d12f8b513522d7e1b90c91327bfd6b4551468bd695b899a57096fbb38c800000000000000012003000000000000000000000000000000000000000000000000000000000002328000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000071700080000000000000000000000000000000000000000000000000000000000000000776f726d686f6c654465706f736974";

  console.log(_parseVAAAlgorand(new Uint8Array(Buffer.from(vaa, "hex"))));

  let result = await userAccount.functionCall({
    contractId: config.wormholeAccount,
    methodName: "verify_vaa",
    args: {
      vaa,
    },
    gas: 100000000000000,
  });

  console.log("test complete");
}

test();
