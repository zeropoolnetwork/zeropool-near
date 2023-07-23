# ZeroPool privacy pool for NEAR

## Overview
`zeropool-near` provides a way to add support for private transactions to any NEAR FT contract.

## Usage
1. Add `ZeropoolState` structure to your contract:
    ```rust
    #[near_bindgen]
    #[derive(BorshDeserialize, BorshSerialize)]
    pub struct Contract {
        //...
        pool: ZeropoolState,
        //...
    }
    ```
2. Construct `ZeropoolState` in your contract's `new` method.:
    ```rust
    let pool = ZeropoolState::new(tx_vk, tree_vk, denominator);
    ```
   * tx_vk and tree_vk are verification keys for the transaction and the merkle tree respectively. See https://github.com/zeropoolnetwork/zeropool-test-params for testing keys/params and more info.
3. Implement ZeroPool methods with the impl_zeropool macro:
    ```rust
    zeropool_near::impl_zeropool!(Contract, pool, token);
    ```

See an example FT implementation in `ft/`.


## Deploy dev contract
Run this command to deploy a basic FT contract with support for lockups and zeropool methods:
```bash
./scripts/deploy-dev
```

## Relayer
https://hub.docker.com/r/voidxnull/zeropool-relayer
https://github.com/zeropoolnetwork/zeropool-relayer-rs

### Configuration
```bash
PORT=3000
BACKEND=near
REDIS_URL=redis://localhost:6379
FEE=0

NEAR_NETWORK=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
NEAR_ARCHIVE_RPC_URL=https://rpc.testnet.internal.near.org
NEAR_SK=secret
NEAR_POOL_ADDRESS=pool.testnet
NEAR_RELAYER_ACCOUNT_ID=relayer.testnet
NEAR_TOKEN_ID=pool.testnet # can be different from NEAR_POOL_ADDRESS
```

## Console
https://hub.docker.com/r/voidxnull/zeropool-console
https://github.com/zeropoolnetwork/zeropool-console

### Configuration
```bash
NETWORK=near
RPC_URL=https://rpc.testnet.near.org
RELAYER_URL=https://url.to.relayer
CONTRACT_ADDRESS=zpcontract.testnet
TOKEN_ADDRESS=zpcontract.testnet

# TODO: Remove dependency on relayer address. For now, it's used when getting transaction metadata for displaying transaction history.
RELAYER_ADDRESS=

TRANSACTION_URL='https://explorer.testnet.near.org/transactions/{{hash}}'
ZP_FAUCET_URL=https://url.to.faucet.service
```


## Faucet service (for console)
https://hub.docker.com/r/voidxnull/zeropool-faucet
https://github.com/zeropoolnetwork/zeropool-faucet

### ENV Configuration
```bash
PORT=80
```

### backends.json
```json
{
    "near": {
        "rpc_url": "https://rpc.testnet.near.org",
        "reset_interval": 60000,
        "tokens": [
            {
                "type": "near",
                "account_id": "voidxnull-zp-faucet.testnet",
                "secret_key": "ed25519:...",
                "limit": "5000000000000000000000000"
            },
            {
                "type": "ft",
                "account_id": "some-ft.testnet",
                "secret_key": "ed25519:...",
                "limit": "10000000000000"
            }
        ]
    }
}
```
