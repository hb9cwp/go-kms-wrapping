# run single a node using pre-release of OpenBao v2.6.0+ from nightly builds
# $ ./bao server -config=openbao/config/openbao_shamir.hcl
# check WebUI at  http://127.0.0.1 which should redirect to http://127.0.0.1/ui
# $ export BAO_ADDR='http://0.0.0.0:8200'
# $ ./bao status
# $ ./bao-2.6.0-nightly1777642855 operator init
# $ ./bao operator unseal
# enter 3 of 5 recovery keys output by init before
#
# Seal migration
#  https://openbao.org/docs/concepts/seal/#seal-migration
# $ ./bao operator unseal -migrate

# Enable the Web UI
ui = true

# Use Integrated Storage (Raft)
storage "raft" {
  path    = "./openbao/data"
  node_id = "node1"
}

# TCP Listener
listener "tcp" {
  address     = "0.0.0.0:8200"
  # Set to 1 for testing; use actual certs for production
  tls_disable = true
}

# from: static example
#  https://openbao.org/docs/configuration/seal/static/#static-example
# to create a sample key:
# $ openssl rand -out /home/rs/tsm/sandbox/config/unseal-20260430-1.key 32
# Note: assert OpenBao can access secret files!
#seal "static" {
#  current_key_id = "20260430-1"
#  current_key = "file:///home/rs/tsm/sandbox/config/unseal-20260430-1.key"
#  previous_key_id = "20260101-1"
#  previous_key = "file:///home/rs/tsm/sandbox/config/unseal-20260101-1.key"
#  disabled = true      # set true If the migration is from Auto seal to Shamir seal, or to another Auto seal!
#}

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

# Advertise the API address for clients
api_addr = "http://127.0.0.1:8200"
# IP must be specific with Raft storage otherwise unseal fails
#cluster_addr = "http://0.0.0.0:8201"
cluster_addr = "http://127.0.0.1:8201"

# disable HA mode, otherwise unseal likely fails once party k of n enters its unseal key share
disable_standby_reads = true
