package signing

// Nolus custom sign modes for Solana-derived ed25519 accounts (issue #233).
// Declared here rather than regenerated into signing.pb.go because the pulsar
// counterpart (cosmossdk.io/api) is not forked; the api side uses numeric casts
// of these same values. The init below extends the generated SignMode_name /
// SignMode_value maps in place so String() and enum lookups resolve the names.
const (
	// SignMode_SIGN_MODE_SOLANA_OFFCHAIN signs the sRFC-38 v1 offchain-message
	// envelope over the transaction's canonical amino JSON, letting Solana
	// wallets that expose solana:signOffchainMessage sign Nolus transactions.
	SignMode_SIGN_MODE_SOLANA_OFFCHAIN SignMode = 192
	// SignMode_SIGN_MODE_SOLANA_TX_CARRIER verifies a wallet-signed Solana
	// transaction that carries the transaction's canonical amino JSON in an SPL
	// Memo instruction, for Solana wallets that can only sign transactions.
	SignMode_SIGN_MODE_SOLANA_TX_CARRIER SignMode = 193
)

func init() {
	SignMode_name[int32(SignMode_SIGN_MODE_SOLANA_OFFCHAIN)] = "SIGN_MODE_SOLANA_OFFCHAIN"
	SignMode_name[int32(SignMode_SIGN_MODE_SOLANA_TX_CARRIER)] = "SIGN_MODE_SOLANA_TX_CARRIER"
	SignMode_value["SIGN_MODE_SOLANA_OFFCHAIN"] = int32(SignMode_SIGN_MODE_SOLANA_OFFCHAIN)
	SignMode_value["SIGN_MODE_SOLANA_TX_CARRIER"] = int32(SignMode_SIGN_MODE_SOLANA_TX_CARRIER)
}
