'''simple example of a pay-to-taproot (p2tr) transaction'''

from bitcointools.schnorr import pubkey_gen, schnorr_sign
from bitcointools.taproot import create_taproot_mast

internal_pubkey_hex = "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329"

# tests our schnorr digital signature functionality
msg = b'The Times /03/Jan/2009 Chancellor on brink of second bailout for banks'
aux_rand = bytes(32)  # 32-byte array of zero bytes

# generate keypair
sk = bytes.fromhex('deadbeef')
pk = pubkey_gen(sk)

sig = schnorr_sign(msg, sk, aux_rand)  # schnorr_sign() verifies the signature before returning it
