# from README.md in Go-KMS-Wrapping - Go library for encrypting values through various KMS providers
#  https://github.com/hashicorp/go-kms-wrapping/README.md


## Usage

# Following is an example usage of the AWS KMS provider. 

// Context used in this library is passed to various underlying provider
// libraries; how it's used is dependent on the provider libraries
ctx := context.Background()

wrapper := awskms.NewWrapper()
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "kms_key_id": "1234abcd-12ab-34cd-56ef-1234567890ab",
}))
if err != nil {
    return err
}
blobInfo, err := wrapper.Encrypt(ctx, []byte("foo"))
if err != nil {
    return err
}

//
// Do some things...
//

plaintext, err := wrapper.Decrypt(ctx, blobInfo)
if err != nil {
    return err
}
if string(plaintext) != "foo" {
    return errors.New("mismatch between input and output")
}