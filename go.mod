module github.com/hashicorp/go-kms-wrapping/v2
//module github.com/hb9cwp/go-kms-wrapping/v2

go 1.20

require (
	github.com/favadi/protoc-go-inject-tag v1.4.0
	github.com/hashicorp/go-uuid v1.0.3
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.8.2
	golang.org/x/crypto v0.6.0
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// from
//  https://github.com/golang/go/issues/39889   which refers to:
//  https://github.com/golang/go/wiki/Modules#when-should-i-use-the-replace-directive
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v2.3.0
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping master
replace github.com/hashicorp/go-kms-wrapping => /home/rs/vaultMPC/tsm/go-kms-wrapping
//replace github.com/hashicorp/go-kms-wrapping => ../go-kms-wrapping crosscom-mpc
//replace github.com/hashicorp/go-kms-wrapping => ../go-kms-wrapping
//replace github.com/hashicorp/go-kms-wrapping/v2 => github.com/hb9cwp/go-kms-wrapping v2.3.0
//replace github.com/hashicorp/go-kms-wrapping/v2 => github.com/hb9cwp/go-kms-wrapping v2
//replace github.com/hashicorp/go-kms-wrapping => github.com/hb9cwp/go-kms-wrapping v2
