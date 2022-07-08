pub mod utils;

use wasm_bindgen::prelude::*;
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Params, Pbkdf2,
};
use rand::{seq::SliceRandom, thread_rng};

use hex::ToHex;
use serde::{Serialize, Deserialize};


extern crate web_sys;

// macro_rules! log {
//     ( $( $t:tt )* ) => {
//         web_sys::console::log_1(&format!( $( $t )* ).into());
//     }
// }

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct FuzzyExtractor {
    source_length: usize,
    cipher_length: usize,
    security_length: usize,
    num_helpers: usize,
    reference_mask: Vec<u8>,
    reference_mask_indices: Vec<usize>,
    hash_rounds: u32,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct FuzzyExtractorResult {
    secret_padded: String,
    ciphers: Vec<String>,
    mask_seed: String,
    nonce_seed: String,
    reference_mask_indices: Vec<usize>
}

impl FuzzyExtractorResult {
    pub fn length(&self) -> usize {
        self.ciphers.len()
    }
    pub fn mask_seed(&self) -> &String{
        &self.mask_seed
    }
    pub fn nonce_seed(&self) -> &String {
        &self.nonce_seed
    }
}


#[wasm_bindgen]
impl FuzzyExtractor {
    pub fn new(
        source_length: usize,
        hamming_error: u32,
        reference_mask: &[u8],
        reproduce_error: f64,
        security_length: usize,
        burned_bit_length: usize,
        hash_rounds: u32,
    ) -> FuzzyExtractor {
        utils::set_panic_hook();
        let cipher_length = source_length + security_length;
        let bit_length = source_length * 8;
        // log!("bit length: {}", bit_length);
        let c = (hamming_error as f64) / (bit_length as f64).ln();
        // log!("c: {}", c);
        let num_helpers =
            ((bit_length as f64).powf(c) * (2.0 / reproduce_error as f64).log2()) as usize;
        // log!("num_helpers: {}", num_helpers);
        let mut reference_mask: Vec<u8> = reference_mask.to_vec();
        // log!("refe_mask : {} ", reference_mask.len());
        let mut ref_mask_ind: Vec<usize> = Vec::new();
        for (i, mask) in reference_mask.iter().enumerate() {
            if *mask == 1 {
                ref_mask_ind.push(i);
            }
        }
        // log!("max of ind: {}, length: {}", ref_mask_ind.iter().max().unwrap(), ref_mask_ind.len());
        // burn bits
        for i in 0..burned_bit_length.min(ref_mask_ind.len()) {
            reference_mask[ref_mask_ind[i]] = 0;
        }
        // shuffle ref_mask_ind
        ref_mask_ind.shuffle(&mut thread_rng());
        let reference_mask_indices: Vec<usize> = (&ref_mask_ind[burned_bit_length..]).to_vec();

        FuzzyExtractor {
            source_length,
            cipher_length,
            security_length,
            num_helpers,
            reference_mask,
            reference_mask_indices,
            hash_rounds,
        }
    }

    pub fn length(&self) -> usize {
        self.num_helpers
    }

    pub fn generate(&self, key_source: &[u8], key_length: usize) -> JsValue {
        // log!("key source length: {}, key length: {}", key_source.len(), key_length);
        let mut secret: Vec<u8> = utils::gen_random_bytes(self.source_length);
        // log!("Secret is {:?}", secret);
        let mut padding: Vec<u8> = vec![0; self.security_length];
        secret.append(&mut padding);
        // log!("Secret with padding is {:?}", secret);
        let params = Params {
            rounds: self.hash_rounds,
            output_length: self.cipher_length,
        };

        let (mask_seed, mut mask_rng) = utils::init_rand();
        let (nonce_seed, mut nonce_rng) = utils::init_rand();
        let n_nums: Vec<usize> = (0..self.reference_mask_indices.len()).collect();

        let ciphers: Vec<_> = (0..self.num_helpers)
            .map(|_| {
                let key_in_bits: Vec<u8> = n_nums.choose_multiple(&mut mask_rng, key_length)
                    .map(|&i| {
                        let idx = self.reference_mask_indices[i];
                        key_source[idx] & self.reference_mask[idx]
                    }).collect();
                let key_in_bytes = utils::bits2bytes(&key_in_bits);
                let salt = SaltString::generate(&mut nonce_rng);
                let hash = Pbkdf2
                    .hash_password_customized(&key_in_bytes, None, None, params, &salt)
                    .unwrap()
                    .hash;
                let digest_i = hash.unwrap();
                let cipher_i = utils::elementwise_xor(digest_i.as_bytes(), &secret); // O(m)

                cipher_i.encode_hex::<String>()
            })
            .collect();

        // log!("Ciphers: {:?}", ciphers);
        let result = FuzzyExtractorResult {
            secret_padded: secret.encode_hex::<String>(),
            nonce_seed: nonce_seed.encode_hex::<String>(),
            ciphers: ciphers,
            mask_seed: mask_seed.encode_hex::<String>(),
            reference_mask_indices: self.reference_mask_indices.clone(),
        };
        JsValue::from_serde(&result).unwrap()
    }

    fn reproduce_internal(
        &self,
        mask_idx: &[usize],
        key_source: &[u8],
        nonce: &SaltString,
        params: Params,
        cipher: &str,
    ) -> Vec<u8> {
        let sample_key_source = utils::sample_by_indices(mask_idx, key_source);
        let sample_mask = utils::sample_by_indices(mask_idx, &self.reference_mask);
        let key_i = utils::bitwise_and(&sample_key_source, &sample_mask);

        let hash = Pbkdf2
            .hash_password_customized(&key_i, None, None, params, nonce.as_salt())
            .unwrap();
        let digest_i = &hash.hash.unwrap().as_bytes().to_vec();
        let cipher_i = hex::decode(cipher).unwrap();
        utils::elementwise_xor(&digest_i, &cipher_i)
        // plain_i.encode_hex::<String>()
    }

    pub fn reproduce(
        &self,
        key_source: &[u8],
        key_length: usize,
        helper: &JsValue,
    ) -> String {
        let params = Params {
            rounds: self.hash_rounds,
            output_length: self.cipher_length,
        };
        let helper_result: FuzzyExtractorResult = helper.into_serde().unwrap();
        let nonce_seed = hex::decode(helper_result.nonce_seed).unwrap();
        let mask_seed = hex::decode(helper_result.mask_seed).unwrap();
        let ciphers = helper_result.ciphers;
        let reference_mask_indices = helper_result.reference_mask_indices;
        let mut mask_rng = utils::get_rng(&mask_seed);
        let n_nums: Vec<usize> = (0..reference_mask_indices.len()).collect();
        let masks_idx: Vec<Vec<usize>> = (0..self.num_helpers)
            .map(|_| {
                let sampled_idx_vec: Vec<usize> = n_nums
                    .choose_multiple(&mut mask_rng, key_length) //
                    .map(|&i| {
                        reference_mask_indices[i]
                    })
                    .collect();
                sampled_idx_vec.to_vec()
            })
            .collect();
        let mut salt_rng = utils::get_rng(&nonce_seed);
        let nonces: Vec<_> = (0..self.num_helpers)
            .map(|_| {
                SaltString::generate(&mut salt_rng)
            })
            .collect();

        let result = (0..ciphers.len()).find(|&i| {
            let plain_i =
                self.reproduce_internal(&masks_idx[i], key_source, &nonces[i], params, &ciphers[i]);

            let sec_token_i: usize = plain_i[self.source_length..]
                .iter()
                .map(|&i| i as usize)
                .sum();
            sec_token_i == 0
        });
        let mut ret = String::new();
        if result.is_some() {
            let i = result.unwrap();
            let plain =
                self.reproduce_internal(&masks_idx[i], key_source, &nonces[i], params, &ciphers[i]);
            ret = plain.encode_hex::<String>();
        }
        ret
    }
}
