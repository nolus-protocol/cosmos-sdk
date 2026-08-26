package signing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	signingv1beta1 "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	txsigning "cosmossdk.io/x/tx/signing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
)

// The pulsar-side enum lives in cosmossdk.io/api, which is not forked, so the API-side
// values are numeric casts of the same wire numbers the fork adds to signing.proto.
const (
	apiSignModeSolanaOffchain  = signingv1beta1.SignMode(192)
	apiSignModeSolanaTxCarrier = signingv1beta1.SignMode(193)
)

type stubSignModeHandler struct {
	mode      signingv1beta1.SignMode
	signBytes []byte
}

func (s stubSignModeHandler) Mode() signingv1beta1.SignMode {
	return s.mode
}

func (s stubSignModeHandler) GetSignBytes(_ context.Context, _ txsigning.SignerData, _ txsigning.TxData) ([]byte, error) {
	return s.signBytes, nil
}

func TestSolanaSignModeWireNumbers(t *testing.T) {
	tests := []struct {
		name string
		mode signing.SignMode
		want int32
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, 192},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, 193},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, int32(tc.mode), "sign mode must keep the wire number the chain and clients agree on")
		})
	}
}

func TestSolanaSignModeNamesRegistered(t *testing.T) {
	tests := []struct {
		name string
		mode signing.SignMode
		want string
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, "SIGN_MODE_SOLANA_OFFCHAIN"},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, "SIGN_MODE_SOLANA_TX_CARRIER"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.mode.String(), "sign mode must render its registered name in error messages")
		})
	}
}

func TestSolanaSignModeValuesRegistered(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want int32
	}{
		{"solana offchain", "SIGN_MODE_SOLANA_OFFCHAIN", 192},
		{"solana tx carrier", "SIGN_MODE_SOLANA_TX_CARRIER", 193},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, signing.SignMode_value[tc.key], "sign mode name must resolve back to its wire number")
		})
	}
}

func TestAPISignModeToInternalAcceptsSolanaModes(t *testing.T) {
	tests := []struct {
		name string
		api  signingv1beta1.SignMode
		want signing.SignMode
	}{
		{"solana offchain", apiSignModeSolanaOffchain, signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN},
		{"solana tx carrier", apiSignModeSolanaTxCarrier, signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := APISignModeToInternal(tc.api)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestInternalSignModeToAPIAcceptsSolanaModes(t *testing.T) {
	tests := []struct {
		name     string
		internal signing.SignMode
		want     signingv1beta1.SignMode
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, apiSignModeSolanaOffchain},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, apiSignModeSolanaTxCarrier},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := internalSignModeToAPI(tc.internal)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSolanaSignModeConversionRoundTrips(t *testing.T) {
	tests := []struct {
		name string
		mode signing.SignMode
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api, err := internalSignModeToAPI(tc.mode)
			require.NoError(t, err)
			back, err := APISignModeToInternal(api)
			require.NoError(t, err)
			require.Equal(t, tc.mode, back)
		})
	}
}

func TestAPISignModeToInternalRejectsUnknownModes(t *testing.T) {
	tests := []struct {
		name string
		api  signingv1beta1.SignMode
	}{
		{"unspecified", signingv1beta1.SignMode_SIGN_MODE_UNSPECIFIED},
		{"below solana offchain", signingv1beta1.SignMode(190)},
		{"between solana modes and nothing", signingv1beta1.SignMode(194)},
		{"far out of range", signingv1beta1.SignMode(9999)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := APISignModeToInternal(tc.api)
			require.Error(t, err, "unregistered sign mode must not resolve to an internal mode")
		})
	}
}

func TestInternalSignModeToAPIRejectsUnknownModes(t *testing.T) {
	tests := []struct {
		name     string
		internal signing.SignMode
	}{
		{"unspecified", signing.SignMode_SIGN_MODE_UNSPECIFIED},
		{"below solana offchain", signing.SignMode(190)},
		{"above solana tx carrier", signing.SignMode(194)},
		{"far out of range", signing.SignMode(9999)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := internalSignModeToAPI(tc.internal)
			require.Error(t, err, "unregistered sign mode must not resolve to an API mode")
		})
	}
}

func TestVerifySignatureAcceptsSolanaModeEd25519Signature(t *testing.T) {
	signBytes := []byte("nolus solana sign bytes")

	tests := []struct {
		name     string
		internal signing.SignMode
		api      signingv1beta1.SignMode
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, apiSignModeSolanaOffchain},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, apiSignModeSolanaTxCarrier},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			privKey := ed25519.GenPrivKey()
			sig, err := privKey.Sign(signBytes)
			require.NoError(t, err)

			handler := txsigning.NewHandlerMap(stubSignModeHandler{mode: tc.api, signBytes: signBytes})

			err = VerifySignature(
				context.Background(),
				privKey.PubKey(),
				txsigning.SignerData{},
				&signing.SingleSignatureData{SignMode: tc.internal, Signature: sig},
				handler,
				txsigning.TxData{},
			)
			require.NoError(t, err)
		})
	}
}

func TestVerifySignatureRejectsSolanaModeSignatureOverOtherBytes(t *testing.T) {
	signBytes := []byte("nolus solana sign bytes")

	tests := []struct {
		name     string
		internal signing.SignMode
		api      signingv1beta1.SignMode
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, apiSignModeSolanaOffchain},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, apiSignModeSolanaTxCarrier},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			privKey := ed25519.GenPrivKey()
			sig, err := privKey.Sign([]byte("some other bytes"))
			require.NoError(t, err)

			handler := txsigning.NewHandlerMap(stubSignModeHandler{mode: tc.api, signBytes: signBytes})

			err = VerifySignature(
				context.Background(),
				privKey.PubKey(),
				txsigning.SignerData{},
				&signing.SingleSignatureData{SignMode: tc.internal, Signature: sig},
				handler,
				txsigning.TxData{},
			)
			require.Error(t, err, "a signature over different bytes must not verify")
		})
	}
}

func TestVerifySignatureRejectsSolanaModeSignatureFromOtherKey(t *testing.T) {
	signBytes := []byte("nolus solana sign bytes")

	tests := []struct {
		name     string
		internal signing.SignMode
		api      signingv1beta1.SignMode
	}{
		{"solana offchain", signing.SignMode_SIGN_MODE_SOLANA_OFFCHAIN, apiSignModeSolanaOffchain},
		{"solana tx carrier", signing.SignMode_SIGN_MODE_SOLANA_TX_CARRIER, apiSignModeSolanaTxCarrier},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := ed25519.GenPrivKey()
			impostor := ed25519.GenPrivKey()
			sig, err := impostor.Sign(signBytes)
			require.NoError(t, err)

			handler := txsigning.NewHandlerMap(stubSignModeHandler{mode: tc.api, signBytes: signBytes})

			err = VerifySignature(
				context.Background(),
				signer.PubKey(),
				txsigning.SignerData{},
				&signing.SingleSignatureData{SignMode: tc.internal, Signature: sig},
				handler,
				txsigning.TxData{},
			)
			require.Error(t, err, "a signature from a different key must not verify")
		})
	}
}
