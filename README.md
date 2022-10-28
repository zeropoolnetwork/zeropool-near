ZeroPool smart contract for Near
================================

Work with the contract
======================
To interact with the contract, you can use the following methods:
1. Call `lock` with deposit (the `approve` method in `zeropoop-support-js`). This is a primitive lockup function used to simulate the `approve` system in Ethereum.
2. Prepare data for a new private transaction on the client (`zeropoop-client-js` can be used to prepare and send the transaction to the relayer).
3. The relayer then can serialize the transaction and send it to the contract (`transact`).

Deploy
======

Step 0: Install near-cli
-------------------------------------

[near-cli] is a command line interface (CLI) for interacting with the NEAR blockchain. It was installed to the local `node_modules` folder when you ran `yarn install`, but for best ergonomics you may want to install it globally:

    yarn install --global near-cli

Or, if you'd rather use the locally-installed version, you can prefix all `near` commands with `npx`

Ensure that it's installed with `near --version` (or `npx near --version`)


Step 1: Create an account for the contract
------------------------------------------

Each account on NEAR can have at most one contract deployed to it. If you've already created an account such as `your-name.testnet`, you can deploy your contract to `zeropool.your-name.testnet`. Assuming you've already created an account on [NEAR Wallet], here's how to create `zeropool.your-name.testnet`:

1. Authorize NEAR CLI, following the commands it gives you:

      near login

2. Create a subaccount (replace `YOUR-NAME` below with your actual account name):

      near create-account zeropool.YOUR-NAME.testnet --masterAccount YOUR-NAME.testnet


Step 2: Deploy
---------------

builds & deploys smart contract to NEAR TestNet:

    ./scripts/deploy-init zeropool.YOUR-NAME.testnet
