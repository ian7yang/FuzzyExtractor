#![feature(test)]
// this doesn't work on wasm yet
extern crate test;
extern crate fuzzy_extractor;

use fuzzy_extractor::utils;
use fuzzy_extractor::FuzzyExtractor;

pub mod constants;

#[bench]
fn fe_generate(b: &mut test::Bencher) {
    let fe = FuzzyExtractor::new(28, 10, &constants::MASK, 0.001,  4,  20, 1);
    b.iter(|| {fe.generate(&constants::KEY_SOURCE, 128)});
}

#[bench]
fn fe_reproduce(b: &mut test::Bencher) {
    let fe = FuzzyExtractor::new(28, 10, &constants::MASK, 0.001,  4,  20, 1);
    let helpers = fe.generate(&constants::KEY_SOURCE, 128);
    b.iter(|| {fe.reproduce(&constants::KEY_SOURCE, 128, &helpers)})
}
