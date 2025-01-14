//module github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2
module github.com/hb9cwp/go-kms-wrapping/wrappers/awskms/v2

go 1.20

//replace github.com/hashicorp/go-kms-wrapping/v2 => ../../go-kms-wrapping/
replace github.com/hashicorp/go-kms-wrapping/v2 => ../../../go-kms-wrapping/

require (
	github.com/aws/aws-sdk-go v1.44.210
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.4.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.9-0.20230228100945-740d2999c798
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.6
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
