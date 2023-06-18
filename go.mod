//module github.com/hashicorp/go-kms-wrapping/v2
module github.com/hb9cwp/go-kms-wrapping/v2

go 1.20

require (
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/hashicorp/go-uuid v1.0.3
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.8.2
	golang.org/x/crypto v0.6.0
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2
	google.golang.org/protobuf v1.30.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.6.1 // indirect
	golang.org/x/sys v0.5.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// from
//  https://github.com/golang/go/issues/39889   which refers to:
//  https://github.com/golang/go/wiki/Modules#when-should-i-use-the-replace-directive
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v2.3.0
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v2.0.9
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v0.7.1
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping master
//replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping
//replace github.com/hashicorp/go-kms-wrapping => ../go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => ../go-kms-wrapping
//replace github.com/hashicorp/go-kms-wrapping/v2 => ../go-kms-wrapping

//replace github.com/hashicorp/go-kms-wrapping/v2/internal/xor => ../go-kms-wrapping/internal/xor
replace github.com/hashicorp/go-kms-wrapping/v2 => github.com/hb9cwp/go-kms-wrapping/v2 v2.3.2

//replace github.com/hashicorp/go-kms-wrapping/v2 => github.com/hb9cwp/go-kms-wrapping v2
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v2

//replace github.com/hashicorp/go-kms-wrapping/v2/aead => github.com/hb9cwp/go-kms-wrapping/v2/aead
//replace github.com/hashicorp/go-kms-wrapping/v2/aead => github.com/hb9cwp/go-kms-wrapping/v2/aead v2.3.0
