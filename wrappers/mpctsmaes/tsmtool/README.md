## tsmtool: Command Line Tool to Generate, List, and Delete AES Keys in Builder Vault MPC TSM

### Description
`tsmtool` is a simple command line tool (CLI) that uses a current version of Builder Vault's Go SDK to probe, generate, list, and delete secret AES 128, 192, and 256 bit keys in distributed TSM cluster nodes. Also, it can perform AES-GCM encrypt and decrypt functions including additional authenticated data (AAD) for quick testing of secure Multi-Party Computations (MPC) using the secret AES key shares by the distributed TSM cluster nodes.

Unlike some other KMS wrappers, such as for ex. AWS KMS, the mpctsmaes wrapper does not generate AES keys "automagically" for auto-unseal, or per-namespace unsel operations etc. Thus use `tsmtool` to generate required secret AES key material before bringing up a KMS plugin with the mpctsmwrapper.

### Distributed Key Generation (DKG)
Note that TSM nodes perform Distributed Key Generation (DKG) to compute their secret AES key shares. Therefore, secret AES keys never exist in one place, e.g. there is no single point of failure/compromise at any moment!

## Build `tsmtool`
```
$ cd tsmtool
$ go get -u
$ go run main.go

or
$ go build -o tsmtool main.go
$ ./tsmtool
tsmtool: CLI tool for managing AES keys in TSM clusters
Usage: tsmtool <command> [flags]

Commands:
  probe     Probes TSM services on specified nodes
  generate  Generates a threshold-shared AES key
  list      Lists key shares across the TSM nodes
  delete    Deletes key shares for a specific key ID
  encrypt   Encrypts a plaintext using a generated AES key
  decrypt   Decrypts a ciphertext using a generated AES key

Use 'tsmtool <command> -h' for command-specific flags.
```

## probe
```
$ LOG_LEVEL=DEBUG go run main.go probe
2026-07-06T14:54:17.576+0200 [INFO]  probe: started
2026-07-06T14:54:17.603+0200 [DEBUG] probe: Connected to node: node=1 RTT=26.663082ms
2026-07-06T14:54:17.605+0200 [DEBUG] probe: Connected to node: node=0 RTT=28.624496ms
2026-07-06T14:54:17.606+0200 [DEBUG] probe: Connected to node: node=2 RTT=29.577839ms
Node 0 (http://localhost:8500):
Version Information:
  SDK Release version : 73.3.0
  Client API          : 64.7
  Client Communication: 33.5
  Node Communication  : 36.2
  Node Configuration  : 28.4
Services:
  KeyManagement  ENABLED
  WrappingKey    ENABLED
  ECDSA          ENABLED
  Schnorr        ENABLED
  Broadcast      DISABLED (Broadcast service is not enabled)
  AES            ENABLED
  HMAC           ENABLED
  RSA            ENABLED
client.ProtocolInformation(): 
  ECDSA         : DKLS23
  ECKCDSA       : N/A
  Schnorr       : SEPD19S
  BLS           : N/A
  Aleo          : N/A
  ECDH          : N/A
  RSA           : ADN06
  AES           : MRZ15
  HMAC          : MRZ15
  AN10922       : N/A
  Broadcast     : N/A
  RFC5649       : 

Node 1 (http://localhost:8501):
Version Information:
  SDK Release version : 73.3.0
  Client API          : 64.7
  Client Communication: 33.5
  Node Communication  : 36.2
  Node Configuration  : 28.4
Services:
  KeyManagement  ENABLED
  WrappingKey    ENABLED
  ECDSA          ENABLED
  Schnorr        ENABLED
  Broadcast      DISABLED (Broadcast service is not enabled)
  AES            ENABLED
  HMAC           ENABLED
  RSA            ENABLED
client.ProtocolInformation(): 
  ECDSA         : DKLS23
  ECKCDSA       : N/A
  Schnorr       : SEPD19S
  BLS           : N/A
  Aleo          : N/A
  ECDH          : N/A
  RSA           : ADN06
  AES           : MRZ15
  HMAC          : MRZ15
  AN10922       : N/A
  Broadcast     : N/A
  RFC5649       : 

Node 2 (http://localhost:8502):
Version Information:
  SDK Release version : 73.3.0
  Client API          : 64.7
  Client Communication: 33.5
  Node Communication  : 36.2
  Node Configuration  : 28.4
Services:
  KeyManagement  ENABLED
  WrappingKey    ENABLED
  ECDSA          ENABLED
  Schnorr        ENABLED
  Broadcast      DISABLED (Broadcast service is not enabled)
  AES            ENABLED
  HMAC           ENABLED
  RSA            ENABLED
client.ProtocolInformation(): 
  ECDSA         : DKLS23
  ECKCDSA       : N/A
  Schnorr       : SEPD19S
  BLS           : N/A
  Aleo          : N/A
  ECDH          : N/A
  RSA           : ADN06
  AES           : MRZ15
  HMAC          : MRZ15
  AN10922       : N/A
  Broadcast     : N/A
  RFC5649       : 

## generate
```
$ go run main.go generate
2026-07-06T14:58:09.290+0200 [INFO]  generateKeys: started
error: -keyid is required
Usage of generate:
  -apikeys string
        Comma-separated TSM API keys
  -bits int
        AES key size in bits: 128, 192, or 256 (default 256)
  -cert string
        Path to client certificate
  -force
        Force overwrite existing keys without prompt
  -key string
        Path to client private key
  -keyid string
        Desired key ID: 1-28 chars, alphanumeric, '_' or '-'
  -minplayers int
        Minimum players (default 2)
  -nodes string
        Comma-separated TSM node URLs
  -pin-key string
        Path to pinned public key
  -threshold int
        Security threshold t (default 1)
exit status 1

$ LOG_LEVEL=DEBUG go run main.go generate -keyid demoAES192-2of3 -bits 192 
2026-07-06T15:01:10.346+0200 [INFO]  generateKeys: started
2026-07-06T15:01:10.369+0200 [DEBUG] generateKeys: Connected to node: node=1 RTT=21.72011ms
2026-07-06T15:01:10.370+0200 [DEBUG] generateKeys: Connected to node: node=2 RTT=23.056754ms
2026-07-06T15:01:10.372+0200 [DEBUG] generateKeys: Connected to node: node=0 RTT=25.268493ms
Checking for existing key "demoAES192-2of3" across 3 node(s)...
Key "demoAES192-2of3" not found on any node — safe to proceed.

AES key generation parameters:
  Key ID (desired) : demoAES192-2of3
  Key size         : 192 bits (24 bytes)
  Players          : [0 1 2]
  Min players      : 2
  Threshold        : 1
  Session ID       : -mEbuiskuVX1NFZdgIBYIQUhplwPG4S9GQzSzoVh-7U

AES key generation succeeded!
  Assigned key ID  : demoAES192-2of3
  Key size         : 192 bits
  Key IDs per node : [demoAES192-2of3 demoAES192-2of3 demoAES192-2of3]
2026-07-06T15:01:11.226+0200 [INFO]  generateKeys: done.
```

## list
```
$ ./tsmtool list
2026-07-06T15:03:08.560+0200 [INFO]  listKeys: started
=== Per-node key shares ===
  node 0: 10 key share(s)
    0PDhKw2DGiC8mXh4Ji6YNpFYdWP8 = 305044684b773244476943386d5868344a6936594e70465964575038
    NSroot_SealAES256-001 = 4e53726f6f745f5365616c4145533235362d303031
    NSroot_SealAES256-002 = 4e53726f6f745f5365616c4145533235362d303032
    NSroot_SealAES256-003 = 4e53726f6f745f5365616c4145533235362d303033
    NSroot_SealAES256-2of3 = 4e53726f6f745f5365616c4145533235362d326f6633
    RSA4096-1 = 525341343039362d31
    RSA4096-2 = 525341343039362d32
    demoAES192-2of3 = 64656d6f4145533139322d326f6633
    rs256-2of3 = 72733235362d326f6633
    testAES_GCM = 746573744145535f47434d
  node 1: 10 key share(s)
    0PDhKw2DGiC8mXh4Ji6YNpFYdWP8 = 305044684b773244476943386d5868344a6936594e70465964575038
    NSroot_SealAES256-001 = 4e53726f6f745f5365616c4145533235362d303031
    NSroot_SealAES256-002 = 4e53726f6f745f5365616c4145533235362d303032
    NSroot_SealAES256-003 = 4e53726f6f745f5365616c4145533235362d303033
    NSroot_SealAES256-2of3 = 4e53726f6f745f5365616c4145533235362d326f6633
    RSA4096-1 = 525341343039362d31
    RSA4096-2 = 525341343039362d32
    demoAES192-2of3 = 64656d6f4145533139322d326f6633
    rs256-2of3 = 72733235362d326f6633
    testAES_GCM = 746573744145535f47434d
  node 2: 11 key share(s)
    0PDhKw2DGiC8mXh4Ji6YNpFYdWP8 = 305044684b773244476943386d5868344a6936594e70465964575038
    NSroot_SealAES256-001 = 4e53726f6f745f5365616c4145533235362d303031
    NSroot_SealAES256-002 = 4e53726f6f745f5365616c4145533235362d303032
    NSroot_SealAES256-003 = 4e53726f6f745f5365616c4145533235362d303033
    NSroot_SealAES256-2of3 = 4e53726f6f745f5365616c4145533235362d326f6633
    NqsLR4uMCRjlT09qtxowhfjyPqTL = 4e71734c5234754d43526a6c5430397174786f7768666a795071544c
    RSA4096-1 = 525341343039362d31
    RSA4096-2 = 525341343039362d32
    demoAES192-2of3 = 64656d6f4145533139322d326f6633
    rs256-2of3 = 72733235362d326f6633
    testAES_GCM = 746573744145535f47434d

=== Union across all nodes (11 unique key IDs) ===
  0PDhKw2DGiC8mXh4Ji6YNpFYdWP8  [3/3 nodes]   AES, by: demoapp, at: 2026-04-26T18:59:09Z, labeled: ''
  NSroot_SealAES256-001  [3/3 nodes]   AES, by: demoapp, at: 2026-05-05T08:51:23Z, labeled: ''
  NSroot_SealAES256-002  [3/3 nodes]   AES, by: demoapp, at: 2026-05-05T10:26:44Z, labeled: ''
  NSroot_SealAES256-003  [3/3 nodes]   AES, by: demoapp, at: 2026-05-05T10:31:31Z, labeled: ''
  NSroot_SealAES256-2of3  [3/3 nodes]   AES, by: demoapp, at: 2026-06-26T13:45:09Z, labeled: ''
  NqsLR4uMCRjlT09qtxowhfjyPqTL  [1/3 nodes]   AES, by: demoapp, at: 2026-04-26T10:48:15Z, labeled: ''
  RSA4096-1  [3/3 nodes]   RSA, by: demoapp, at: 2026-06-21T08:12:09Z, labeled: ''
  RSA4096-2  [3/3 nodes]   RSA, by: demoapp, at: 2026-05-12T08:43:30Z, labeled: ''
  demoAES192-2of3  [3/3 nodes]   AES, by: demoapp, at: 2026-07-06T13:01:11Z, labeled: ''
  rs256-2of3  [3/3 nodes]   AES, by: demoapp, at: 2026-07-06T09:20:02Z, labeled: ''
  testAES_GCM  [3/3 nodes]   AES, by: demoapp, at: 2026-06-20T18:19:54Z, labeled: ''

=== Keys present on all 3 reachable node(s) ===
  0PDhKw2DGiC8mXh4Ji6YNpFYdWP8
  NSroot_SealAES256-001
  NSroot_SealAES256-002
  NSroot_SealAES256-003
  NSroot_SealAES256-2of3
  RSA4096-1
  RSA4096-2
  demoAES192-2of3
  rs256-2of3
  testAES_GCM
2026-07-06T15:03:08.629+0200 [INFO]  listKeys: done.
```

## encrypt
```
$ LOG_LEVEL=DEBUG ./tsmtool encrypt -keyid rs256-2of3
2026-07-06T15:22:48.302+0200 [INFO]  encrypt: started
2026-07-06T15:22:48.302+0200 [DEBUG] encrypt: input: plaintext="The quick brown fox jumps over the lazy dog's back 0123456789."
2026-07-06T15:22:48.321+0200 [DEBUG] encrypt: Connected to node: node=1 RTT=18.508651ms
2026-07-06T15:22:48.324+0200 [DEBUG] encrypt: Connected to node: node=2 RTT=21.141802ms
2026-07-06T15:22:48.326+0200 [DEBUG] encrypt: Connected to node: node=0 RTT=22.72705ms
2026-07-06T15:22:48.993+0200 [DEBUG] encrypt: AES().GCMEncrypt(): player=2 RTT=666.768752ms
2026-07-06T15:22:48.993+0200 [DEBUG] encrypt: AES().GCMEncrypt(): player=0 RTT=666.88266ms
2026-07-06T15:22:48.993+0200 [DEBUG] encrypt: AES().GCMEncrypt(): player=1 RTT=667.628769ms
2026-07-06T15:22:48.994+0200 [DEBUG] encrypt: AESFinalizeGCMEncrypt(): RTT=667.880011ms
Encryption successful!
  Ciphertext : fe5a08d0a0bbb085b7341b84a7a3151ed0aad6108395c45596d33283cb9b18a56387d41a9b280c56c989b0015fddc46e7ba6376f3f6c4922757dcbb5121b
  IV         : 48956574bb696dca7e0e3334
  Tag        : a1cbf695213e497b3b93d26320572a5a
2026-07-06T15:22:48.994+0200 [INFO]  encrypt: done.
```

## decrypt
```
$ LOG_LEVEL=DEBUG ./tsmtool decrypt -keyid rs256-2of3 -ciphertext fe5a08d0a0bbb085b7341b84a7a3151ed0aad6108395c45596d33283cb9b18a56387d41a9b280c56c989b0015fddc46e7ba6376f3f6c4922757dcbb5121b -iv 48956574bb696dca7e0e3334 -tag a1cbf695213e497b3b93d26320572a5a
2026-07-06T15:23:57.484+0200 [INFO]  decrypt: started
2026-07-06T15:23:57.503+0200 [DEBUG] decrypt: Connected to node: node=0 RTT=18.552424ms
2026-07-06T15:23:57.503+0200 [DEBUG] decrypt: Connected to node: node=1 RTT=18.56976ms
2026-07-06T15:23:57.505+0200 [DEBUG] decrypt: Connected to node: node=2 RTT=20.736701ms
2026-07-06T15:23:58.163+0200 [DEBUG] decrypt: AES().GCMDecrypt(): player=1 RTT=657.903843ms
2026-07-06T15:23:58.163+0200 [DEBUG] decrypt: AES().GCMDecrypt(): player=0 RTT=658.020203ms
2026-07-06T15:23:58.165+0200 [DEBUG] decrypt: AES().GCMDecrypt(): player=2 RTT=659.740252ms
2026-07-06T15:23:58.165+0200 [DEBUG] decrypt: AESFinalizeGCMDecrypt(): RTT=660.24148ms
Decryption successful!
  Plaintext : The quick brown fox jumps over the lazy dog's back 0123456789.
2026-07-06T15:23:58.165+0200 [INFO]  decrypt: done.
```

## delete
```
$ ./tsmtool delete -keyid demoAES192-2of3
2026-07-06T15:29:18.986+0200 [INFO]  deleteKeys: started

 WARNING: key shares with keyID "demoAES192-2of3" exist 
 Found on nodes: [0 1 2] 

 Proceeding will PERMANENTLY DELETE these key shares. 
 This action cannot be undone. 

 Type "yes" to delete, or anything else to abort: yes
Key shares deleted successfully!
2026-07-06T15:29:21.369+0200 [INFO]  deleteKeys: done.
```

