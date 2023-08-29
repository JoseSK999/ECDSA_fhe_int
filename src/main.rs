use std::array;
use primitive_types::{U256, U512};
use rand::{Rng, thread_rng};

use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey, U256 as fheU256, U512 as fheU512};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};

const N_BYTES: [u8; 64] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65];

fn main() {
    let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, 256);
    let secp = Secp256k1::new();

    // Generate secp256k1 secret key
    let mut random = thread_rng();
    let secret = array::from_fn::<u8, 32, _>(|_| random.gen());
    let secret_key = SecretKey::from_slice(&secret)
        .expect("32 bytes, within curve order");

    // Generate and encrypt the private ECDSA inputs
    let (r, mut nonce_inv, mut prv_key) = encrypt_ecdsa_input(&secret, &ck);

    let mut nonce_pub = fheU256::from(0u8);
    nonce_pub.copy_from_be_byte_slice(&r);

    let message_bytes = array::from_fn::<u8, 32, _>(|_| random.gen());
    let mut message = fheU256::from(0u8);
    message.copy_from_be_byte_slice(&message_bytes);

    // Signature computation
    let result = sign_ecdsa(
        &mut prv_key,
        &mut nonce_inv,
        nonce_pub,
        message,
        &sk,
    );

    // Decrypt
    let decrypted: fheU512 = ck.decrypt(&result);

    // There are 64 bytes but our result is 32 bytes as it's reduced mod N
    let mut s = [0u8; 64];
    decrypted.copy_to_be_byte_slice(&mut s);
    let raw_sig = [r, s[32..].try_into().unwrap()].concat();

    // Verify
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(&message_bytes).unwrap();
    let mut sig = Signature::from_compact(&raw_sig).unwrap();

    // The value 's' must be in the lower half of the allowable range to be valid according to the
    // libsecp256k1 library. This constraint is in place to prevent signature malleability, as
    // specified by BIP 146. Signature malleability occurs when there is more than one valid
    // signature for the same transaction. By restricting 's' to the lower half, the signature
    // becomes unique and non-malleable.
    sig.normalize_s();

    assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    println!("Success!");
}

fn sign_ecdsa(
    private_key: &mut RadixCiphertext,
    nonce_inverse: &mut RadixCiphertext,
    nonce_pub: fheU256,
    message: fheU256,
    sk: &ServerKey,
) -> RadixCiphertext {
    let mut n = fheU512::from(0u8);
    n.copy_from_be_byte_slice(&N_BYTES);
    println!("start");

    // priv key * public nonce (x coordinate)
    let mut result = sk.smart_scalar_mul_parallelized(private_key, nonce_pub);
    println!("mul scalar");
    sk.smart_scalar_rem_assign_parallelized(&mut result, n);
    println!("reduction");

    // + message
    sk.smart_scalar_add_assign_parallelized(&mut result, message);
    println!("add");
    // If result is >= N, return result - N, otherwise return result
    let mut condition = sk.smart_scalar_ge_parallelized(&mut result, n);
    let mut subtracted = sk.smart_scalar_sub_parallelized(&mut result, n);

    result = sk.smart_if_then_else_parallelized(&mut condition, &mut subtracted, &mut result);
    println!("reduction");

    // * nonce inverse
    sk.smart_mul_assign_parallelized(&mut result, nonce_inverse);
    println!("mul cipher");
    sk.smart_scalar_rem_parallelized(&mut result, n)
}

fn encrypt_ecdsa_input(secret_key: &[u8; 32], ck: &RadixClientKey) -> ([u8; 32], RadixCiphertext, RadixCiphertext) {
    let secp = Secp256k1::new();
    let mut random = thread_rng();

    // Nonce pub key
    let nonce = array::from_fn::<u8, 32, _>(|_| random.gen());
    let nonce_pub = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&nonce).expect("32 bytes, within curve order"),
    ).serialize();

    // Nonce modular inverse
    let mut nonce_inverse = fheU256::from(0u8);
    nonce_inverse.copy_from_be_byte_slice(&modular_inverse(&nonce));

    let mut priv_k = fheU256::from(0u8);
    priv_k.copy_from_be_byte_slice(secret_key);

    let d = ck.encrypt(priv_k);
    let k = ck.encrypt(nonce_inverse);
    let r = array::from_fn(|i| nonce_pub[i+1]);

    (r, k, d)
}

fn modular_inverse(base: &[u8; 32]) -> [u8; 32] {
    let base = U256::from_big_endian(base);
    let p = U256::from_dec_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();

    let mut res = U512::one();
    let mut x = U512::from(base % p);
    let mut y = p - U256::from(2);

    while y > U256::zero() {
        if y % U256::from(2) != U256::zero() {
            res = (res * x) % p;
        }
        y /= U256::from(2);
        x = (x * x) % p;
    }

    let mut bytes = [0u8; 64];
    res.to_big_endian(&mut bytes);

    array::from_fn(|i| bytes[i+32])
}