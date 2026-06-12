#mpctsmaes: Add Blockdaemon Builder Vault MPC TSM KMS Wrapper

### Description
This PR introduces a new KMS wrapper that provides native integration of Threshold Security modules (TSM) using the [Builder Vault](https://builder-vault-tsm.docs.blockdaemon.com/docs/homepage) [Go SDK v2](https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-demo-tsm-golang) by Blockdaemon [on GitLab](https://gitlab.com/Blockdaemon/go-tsm-sdkv2) and distributed clusters with Secure Multi-Party Computation (MPC).

### Cryptographic Architecture
This first version of the TSM wrapper uses double AES-256-GCM envelope encryption where the AES Key Encryption Key (KEK) never exists in a single place. A simple command line tool provisions secret keys in the TSM using Distributed Key Generation (DKG).
Further, cryptographic binding using Authenticated Additional Data (AAD) of GCM between the inner and outer encryption prevents attacks such as ciphertext substitution, context confusion, and cut-and-paste attacks.

### Features & Scope
Designed for the upcoming **OpenBao v2.6.0** release, this wrapper and its [KMS Plugin](https://github.com/openbao/openbao-plugins/pull/999) support:
* Auto-unseal
* Per-namespace sealing
* Scoped logging for testing, debugging, and monitoring

Support for external keys and offloading selected cryptographic operations to the TSM KMS may follow in subsequent updates.

### Future Roadmap & Dependencies
A future version may introduce hybrid encryption using AES-256-GCM for inner symmetric encryption/encapsulation by Data Encryption Key (DEK) and RSA-OAEP for outer asymmetric encryption of the KEK. 
This roadmap depends on Blockdaemon adding support in the Builder Vault TSM for DKG of RSA key pairs and proactive refreshing of distributed private RSA key shares to ensure private keys never exist in a single place.
Cryptographic binding between the inner and outer encryption layers will be maintained via AAD in Galois Counter Mode (GCM)
and labels in Optimal Asymmetric Encryption Padding (OAEP).

### Deployment & Comparison
These native TSM wrappers with their KMS plugins serve as an alternative or replacement for integrations via PKCS#11 libraries provided by Blockdaemon for Builder Vault TSM. 
They make TSM usage as simple and safe as other cloud KMS providers, fitting seamlessly into existing GitOps workflows. 

TSM clusters are cloud-native, software-only, single statically linked Go binaries. They are containerized and packaged via Helm charts by Blockdaemon for self-hosting on private or public clouds, optional in secure enclaves, and WebAssembly run-times (both server-side and in-browser).

### Testing & Evaluation
For quick testing and evaluation, you can register for Blockdaemon's ["Hosted Sandbox"](https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-hosted-sandbox) portal, which provides 30 days of free access immediatly to a 3-node TSM cluster running on AWS. 

We provide a sample `openbao.hcl` configuration file with pre-configured `plugin` and `seal` stanzas. 
It illustrates how OpenBao can connect to the Hosted TSM Sandbox using the certificates provided during registration.

