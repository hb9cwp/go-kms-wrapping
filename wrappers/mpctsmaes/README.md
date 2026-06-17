
## mpctsmaes: Add Blockdaemon Builder Vault MPC TSM KMS Wrapper

### Description
This PR introduces a new KMS wrapper that provides native integration of Threshold Security modules (TSM) using the [Builder Vault](https://builder-vault-tsm.docs.blockdaemon.com/docs/homepage) [Go SDK v2](https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-demo-tsm-golang) by Blockdaemon [on GitLab](https://gitlab.com/Blockdaemon/go-tsm-sdkv2) and distributed clusters with Secure Multi-Party Computation (MPC).

### Cryptographic Architecture
This first version of the TSM wrapper uses double AES-256-GCM envelope encryption where AES Key Encryption Keys (KEK) never exist in a single place. A simple command line tool provisions secret keys in the TSM using Distributed Key Generation (DKG).
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

### References
1. Prof. Yehuda Lindell. *CORE Key Management – Advancing HSMs* (Video from Whiteboard Session).
   Unbound Security Labs (Coinbase aquired Unbound in November 2021), Apr 4, 2021.
   https://www.youtube.com/watch?v=xw5tFz7MGDM

2. Prof. Ivan Damgård. *Secure Computation and Key Management* (Keynote).
   Partisia Foundation / Aarhus University (Blockdaemon acquired Sepior with TSM v1 in July 2022), MPC Alliance, Nov 2, 2022.
   https://www.youtube.com/watch?v=RMJZ2moMqKw

3. Prof. Ivan Damgård. *Thirty-five years of MPC* (Podcast).
   Partisia Blockchain Foundation, Dec 20, 2023.
   https://www.youtube.com/watch?v=EcTl0ncaIDs

4. Prof. Yehuda Lindell. *New Directions in Software Key Protection* (Talk, at minute 56:55 about _key management & protection using secure computation of RSA functions by MPC, proactice refresh of private RSA key shares, table with_ ***comparison of HSMs vs. Secure Elements vs. TEE vs. MPC***, _NIST abut *FIPS 140* protection levels with MPC_).
   Unbound Security Labs, Crypto Breakfast, 2019.
   https://youtu.be/NTJg04-_Q7Q?si=8xqkESppR0EFq5RR&t=3415

5. Prof. Yehuda Lindell. *Secure Multiparty Computation - MPC has moved from theoretical study to real-world usage. How is it doing?* (Review Article from CACM).
   Communications of the ACM, Vol. 64 No. 1, Pages: 86-96, Jan 1 2021.
   https://cacm.acm.org/research/secure-multiparty-computation/ , https://eprint.iacr.org/2020/300.pdf

6. David Evans, Vladimir Kolesnikov and Mike Rosulek. *A Pragmatic Introduction to Secure Multi-Party Computation* (Text Book in PDF).
   NOW Publishers, December 2018, Last update: 11 June 2022.
   https://securecomputation.org/index.html

### Appendix A. Sample OpenBao Configuration with TSM Wrappers & KMS Plugins
```
...
# Must be a real directory (not a symlink) and bao have rx permission
plugin_directory = "/home/rs/openbao/openbao-plugins_rs"
#plugin_auto_download = false

# RFC Auto Unseal Plugins: User-facing Description
#  https://openbao.org/docs/next/rfcs/auto-unseal-plugins/#user-facing-description
# Complete example
#  https://openbao.org/docs/next/configuration/plugins/#complete-example

## AWS KMS
plugin "kms" "aws" {   # start gRPC server process of plugin with AWS KMS wrapper, from 2.6.x and later
  command     = "openbao-plugin-kms-aws"
  sha256sum = "9048ce4166022b9e9756fa2a5ffd00e9edfc3e26ebbfbad6edd17812cda7dec4"
}

# awskms example: access AWS KMS emulation "nsmithuk/local-kms" (Go that runs local)
#  https://openbao.org/docs/next/configuration/seal/awskms/
# $ aws kms list-keys --endpoint=http://localhost:8080
#seal "awskms" {                # use AWS KMS wrapper compiled into OpenBao binary, up to v2.6.x
seal "aws" {                    # use plugin of AWS KMS wrapper, from 2.6.x and later
  region     = "eu-west-2"
  access_key = "111122223333"
  secret_key = "111122223333"
  endpoint   = "http://localhost:8080"
  kms_key_id = "d0707863-1244-4d53-91fe-90fcb5f887a3"
  #disabled = true      # set true If the migration is from Auto seal to Shamir seal, or to another Auto seal!
}

## TSM with double AES-256-GCM encryption
plugin "kms" "mpctsmaes" {  # start gRPC server process of plugin with TSM wrapper, from 2.6.x and later
  command     = "openbao-plugin-kms-mpctsmaes"
  sha256sum = "8a3b860df5df3dd17ca1eeae16efef6272011f05d38534831c61d413c0a87295"
}

# TSM example: access TSM cluster
seal "mpctsmaes" {           # use plugin of TSM wrapper
  parties = 3
  threshold = 1
  # access Local Deployment of TSM cluster run by Docker Compose
    #node_url = "http://localhost:8500,http://localhost:8501,http://localhost:8502"  # TSM_NODE_URL
    #node_apikey = "apikey0,apikey1,apikey2"  # TSM_NODE_APIKEY
  # access Hosted Sandbox of TSM cluster that Blockdaemon runs on AWS
    node_url = "https://tsm-sandbox.prd.wallet.blockdaemon.app:8080,https://tsm-sandbox.prd.wallet.blockdaemon.app:8081,https://tsm-sandbox.prd.wallet.blockdaemon.app:8082"
    node_client_key_0 = "file:///home/rs/tsm/sandbox/config/client0.key"	# or set env var MPCTSM_CLIENT_KEY
    node_client_key_1 = "file:///home/rs/tsm/sandbox/config/client1.key"
    node_client_key_2 = "file:///home/rs/tsm/sandbox/config/client2.key"
    node_client_cert_0 = "file:///home/rs/tsm/sandbox/config/client0.crt"	# or set env var MPCTSM_CLIENT_CERT
    node_client_cert_1 = "file:///home/rs/tsm/sandbox/config/client1.crt"
    node_client_cert_2 = "file:///home/rs/tsm/sandbox/config/client2.crt"
  key_id = "NSroot_SealAES256-001"	# symmetric AES 256 bit key must be pre-provisionned by some managenent tool using TSM SDKv2
  #disabled = true      # set true If the migration is from Auto seal to Shamir seal, or to another Auto seal!
}
...
```


### TODO
- [ ] Fix link to PR in openbao-plugins once its #nn is known.
- [ ] Provide a simple command line tool to provision AES keys in TSM clusters, e.g. create, list, delete distributed symmetric key shares and eventually safely backup/restore using the TSM enpoints and credentials from `openbao.hcl` or equivalent env vars.
- [ ] Verify `go test` passes all unit tests against the Hosted Sandbox once Blockdaemon upgrades its TSM cluster nodes to LTS (currently v73.2.0), and enables additional TSM features such as support for AES.
