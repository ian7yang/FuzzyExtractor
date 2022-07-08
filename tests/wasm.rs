#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;
// wasm_bindgen_test_configure!(run_in_browser);


extern crate fuzzy_extractor;

use fuzzy_extractor::{ FuzzyExtractor, FuzzyExtractorResult};
pub mod constants;

#[cfg(test)]
pub fn new_fe(source_length: usize,
    hamming_error: u32,) -> FuzzyExtractor {
    FuzzyExtractor::new(source_length, hamming_error, &constants::MASK, 0.001,  4,  20, 1)
}


#[wasm_bindgen_test]
pub fn test_cipher_length() {
    let fe = new_fe(28, 7);
    let helper = fe.generate(&constants::KEY_SOURCE, 128);
    let result: FuzzyExtractorResult = helper.into_serde().unwrap();
    assert_eq!(fe.length(), result.length());
}

#[wasm_bindgen_test]
pub fn test_reproduce() {
    let fe = new_fe(28, 7);
    let result = fe.generate(&constants::KEY_SOURCE, 128);
    let sec = fe.reproduce(&constants::KEY_SOURCE, 128, &result);
    assert_ne!(sec, "");
    assert!(sec.ends_with("0000"));
}
