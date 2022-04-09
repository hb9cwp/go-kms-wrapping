package wrapping

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-kms-wrapping/v2/internal/xor"
)

// TestWrapper is a wrapper that can be used for tests
type TestWrapper struct {
	wrapperType WrapperType
	secret      []byte
	keyId       string

	envelope bool
}

type TestInitFinalizer struct {
	*TestWrapper
}

type TestInitFinalizerHmacComputer struct {
	*TestInitFinalizer
}

var (
	_ Wrapper       = (*TestWrapper)(nil)
	_ KeyExporter   = (*TestWrapper)(nil)
	_ InitFinalizer = (*TestInitFinalizer)(nil)
	_ KeyExporter   = (*TestInitFinalizer)(nil)
	_ InitFinalizer = (*TestInitFinalizerHmacComputer)(nil)
	_ HmacComputer  = (*TestInitFinalizerHmacComputer)(nil)
	_ KeyExporter   = (*TestInitFinalizerHmacComputer)(nil)
)

// NewTestWrapper constructs a test wrapper
func NewTestWrapper(secret []byte) *TestWrapper {
	return &TestWrapper{
		wrapperType: WrapperTypeTest,
		secret:      secret,
		keyId:       "static-key",
	}
}

// NewTestInitFinalizer constructs a test wrapper
func NewTestInitFinalizer(secret []byte) *TestInitFinalizer {
	return &TestInitFinalizer{
		TestWrapper: &TestWrapper{
			wrapperType: WrapperTypeTest,
			secret:      secret,
			keyId:       "static-key",
		},
	}
}

// NewTestInitFinalizerHmacComputer constructs a test wrapper
func NewTestInitFinalizerHmacComputer(secret []byte) *TestInitFinalizerHmacComputer {
	return &TestInitFinalizerHmacComputer{
		TestInitFinalizer: &TestInitFinalizer{
			TestWrapper: &TestWrapper{
				wrapperType: WrapperTypeTest,
				secret:      secret,
				keyId:       "static-key",
			},
		},
	}
}

// NewTestWrapper constructs a test wrapper
func NewTestEnvelopeWrapper(secret []byte) *TestWrapper {
	return &TestWrapper{
		wrapperType: WrapperTypeTest,
		secret:      secret,
		keyId:       "static-key",
		envelope:    true,
	}
}

// HmacKeyId returns the HMAC key id
func (t *TestInitFinalizerHmacComputer) HmacKeyId(_ context.Context) (string, error) {
	return "hmac-key", nil
}

// Init initializes the test wrapper
func (t *TestInitFinalizer) Init(_ context.Context, _ ...Option) error {
	return nil
}

// Finalize finalizes the test wrapper
func (t *TestInitFinalizer) Finalize(_ context.Context, _ ...Option) error {
	return nil
}

// Type returns the type of the test wrapper
func (t *TestWrapper) Type(_ context.Context) (WrapperType, error) {
	return t.wrapperType, nil
}

// KeyId returns the configured key ID
func (t *TestWrapper) KeyId(_ context.Context) (string, error) {
	return t.keyId, nil
}

// SetConfig sets config, but there is currently nothing to set on test wrappers
func (t *TestWrapper) SetConfig(_ context.Context, _ ...Option) (*WrapperConfig, error) {
	return nil, nil
}

// HmacKeyId returns the configured HMAC key ID
func (t *TestWrapper) HmacKeyId(_ context.Context) string {
	return ""
}

// SetKeyID allows setting the test wrapper's key ID
func (t *TestWrapper) SetKeyId(k string) {
	t.keyId = k
}

// KeyBytes returns the current key bytes
func (t *TestWrapper) KeyBytes(context.Context) ([]byte, error) {
	if t.secret == nil {
		return nil, fmt.Errorf("missing bytes: %w", ErrInvalidParameter)
	}
	return t.secret, nil
}

// Encrypt allows encrypting via the test wrapper
func (t *TestWrapper) Encrypt(ctx context.Context, plaintext []byte, opts ...Option) (*BlobInfo, error) {
	switch t.envelope {
	case true:
		env, err := EnvelopeEncrypt(plaintext, nil)
		if err != nil {
			return nil, fmt.Errorf("error wrapping data: %w", err)
		}
		ct, err := t.obscureBytes(env.Key)
		if err != nil {
			return nil, err
		}

		keyId, err := t.KeyId(ctx)
		if err != nil {
			return nil, err
		}

		return &BlobInfo{
			Ciphertext: env.Ciphertext,
			Iv:         env.Iv,
			KeyInfo: &KeyInfo{
				KeyId:      keyId,
				WrappedKey: ct,
			},
		}, nil

	default:
		ct, err := t.obscureBytes(plaintext)
		if err != nil {
			return nil, err
		}

		keyId, err := t.KeyId(ctx)
		if err != nil {
			return nil, err
		}

		return &BlobInfo{
			Ciphertext: ct,
			KeyInfo: &KeyInfo{
				KeyId: keyId,
			},
		}, nil
	}
}

// Decrypt allows decrypting via the test wrapper
func (t *TestWrapper) Decrypt(_ context.Context, dwi *BlobInfo, opts ...Option) ([]byte, error) {
	switch t.envelope {
	case true:
		keyPlaintext, err := t.obscureBytes(dwi.KeyInfo.WrappedKey)
		if err != nil {
			return nil, err
		}
		envInfo := &EnvelopeInfo{
			Key:        keyPlaintext,
			Iv:         dwi.Iv,
			Ciphertext: dwi.Ciphertext,
		}
		plaintext, err := EnvelopeDecrypt(envInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
		}
		return plaintext, nil
	default:

		return t.obscureBytes(dwi.Ciphertext)
	}
}

// obscureBytes is a helper to simulate "encryption/decryption"
// on protected values.
func (t *TestWrapper) obscureBytes(in []byte) ([]byte, error) {
	out := make([]byte, len(in))

	if len(t.secret) != 0 {
		// make sure they are the same length
		localSecret := make([]byte, len(in))
		copy(localSecret, t.secret)

		var err error

		out, err = xor.XorBytes(in, localSecret)
		if err != nil {
			return nil, err
		}

	} else {
		// if there is no secret, simply reverse the string
		for i := 0; i < len(in); i++ {
			out[i] = in[len(in)-1-i]
		}
	}

	return out, nil
}