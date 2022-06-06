// npx pretty-quick

const sha256 = require("js-sha256");
const nearAPI = require("near-api-js");
const fs = require("fs").promises;
const assert = require("assert").strict;
const fetch = require("node-fetch");
const elliptic = require("elliptic");
const web3Utils = require("web3-utils");
const nearApi = require("near-api-js");
import { zeroPad } from "@ethersproject/bytes";
import { NodeHttpTransport } from "@improbable-eng/grpc-web-node-http-transport";

import { Account as nearAccount } from "near-api-js";
const BN = require("bn.js");

import { TestLib } from "./testlib";

import {
  ChainId,
  CHAIN_ID_ALGORAND,
  CHAIN_ID_NEAR,
} from "@certusone/wormhole-sdk/lib/cjs/utils";

import {
  attestNearFromNear,
  attestTokenFromNear,
  createWrappedOnNear,
  getForeignAssetNear,
  getIsTransferCompletedNear,
  getIsWrappedAssetNear,
  getOriginalAssetNear,
  redeemOnNear,
  transferNearFromNear,
  transferTokenFromNear,
  getSignedVAAWithRetry,
  CONTRACTS,
} from "@certusone/wormhole-sdk";

const wh = require("@certusone/wormhole-sdk");

import { _parseVAAAlgorand } from "@certusone/wormhole-sdk/lib/cjs/algorand";

function getConfig(env: any) {
  switch (env) {
    case "sandbox":
    case "local":
      return {
        networkId: "sandbox",
        nodeUrl: "http://localhost:3030",
        masterAccount: "test.near",
        wormholeAccount: "wormhole.test.near",
        tokenAccount: "token.test.near",
        userAccount:
          Math.floor(Math.random() * 10000).toString() + "user.test.near",
      };
  }
  return {};
}

export function logNearGas(result: any, comment: string) {
  const { totalGasBurned, totalTokensBurned } = result.receipts_outcome.reduce(
    (acc: any, receipt: any) => {
      acc.totalGasBurned += receipt.outcome.gas_burnt;
      acc.totalTokensBurned += nearAPI.utils.format.formatNearAmount(
        receipt.outcome.tokens_burnt
      );
      return acc;
    },
    {
      totalGasBurned: result.transaction_outcome.outcome.gas_burnt,
      totalTokensBurned: nearAPI.utils.format.formatNearAmount(
        result.transaction_outcome.outcome.tokens_burnt
      ),
    }
  );
  console.log(
    comment,
    "totalGasBurned",
    totalGasBurned,
    "totalTokensBurned",
    totalTokensBurned
  );
}

export function parseSequenceFromLogNear(result: any): [number, string] {
  let sequence = "";
  for (const o of result.receipts_outcome) {
    for (const l of o.outcome.logs) {
      if (l.startsWith("EVENT_JSON:")) {
        const body = JSON.parse(l.slice(11));
        if (body.standard == "wormhole" && body.event == "publish") {
          return [body.seq, body.emitter];
        }
      }
    }
  }
  return [-1, ""];
}

async function testNearSDK() {
  let config = getConfig(process.env.NEAR_ENV || "sandbox");

  // Retrieve the validator key directly in the Tilt environment
  const response = await fetch("http://localhost:3031/validator_key.json");

  const keyFile = await response.json();

  let masterKey = nearAPI.utils.KeyPair.fromString(
    keyFile.secret_key || keyFile.private_key
  );
  let masterPubKey = masterKey.getPublicKey();

  let keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  keyStore.setKey(config.networkId, config.masterAccount, masterKey);

  let near = await nearAPI.connect({
    deps: {
      keyStore,
    },
    networkId: config.networkId,
    nodeUrl: config.nodeUrl,
  });
  let masterAccount = new nearAPI.Account(
    near.connection,
    config.masterAccount
  );

  console.log(
    "Finish init NEAR masterAccount: " +
      JSON.stringify(await masterAccount.getAccountBalance())
  );

  let userKey = nearAPI.utils.KeyPair.fromRandom("ed25519");
  keyStore.setKey(config.networkId, config.userAccount, userKey);

  console.log(
    "creating a user account: " +
      config.userAccount +
      " with key " +
      userKey.getPublicKey()
  );

  await masterAccount.createAccount(
    config.userAccount,
    userKey.getPublicKey(),
    new BN(10).pow(new BN(27))
  );
  const userAccount = new nearAPI.Account(near.connection, config.userAccount);

  console.log(
    "Creating new random non-wormhole token and air dropping some tokens to myself"
  );

  let randoToken = nearApi.providers.getTransactionLastResult(
    await userAccount.functionCall({
      contractId: "test.test.near",
      methodName: "deploy_ft",
      args: {
        account: userAccount.accountId,
      },
      gas: 300000000000000,
    })
  );

  console.log(config);

  console.log(CONTRACTS.DEVNET.near);

  let token_bridge = CONTRACTS.DEVNET.near.token_bridge;

  {
    console.log("attesting: " + randoToken);
    let s = await attestTokenFromNear(userAccount, token_bridge, randoToken);
    const { vaaBytes: signedVAA } = await getSignedVAAWithRetry(
      ["http://localhost:7071"],
      CHAIN_ID_NEAR,
      s[1],
      s[0].toString(),
      {
        transport: NodeHttpTransport(),
      }
    );

    console.log("vaa: " + Buffer.from(signedVAA).toString("hex"));
    let p = _parseVAAAlgorand(signedVAA);
    console.log(await getForeignAssetNear(userAccount, token_bridge, p.FromChain as ChainId, p.Contract as string));
  }

  {
    console.log("attesting Near itself");
    let s = await attestNearFromNear(userAccount, token_bridge);

    const { vaaBytes: signedVAA } = await getSignedVAAWithRetry(
      ["http://localhost:7071"],
      CHAIN_ID_NEAR,
      s[1],
      s[0].toString(),
      {
        transport: NodeHttpTransport(),
      }
    );

    console.log("vaa: " + Buffer.from(signedVAA).toString("hex"));
//    let p = _parseVAAAlgorand(signedVAA);
  }
}

testNearSDK();
