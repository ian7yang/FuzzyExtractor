use std::fs::File;
use std::io::Read;
use std::convert::TryInto;

use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::OsRng;
use rand_hc::Hc128Rng;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(&filename).expect(format!("no file found for {}", filename).as_str());
    let metadata = f.metadata().expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

pub fn gen_random_bytes(size: usize) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::with_capacity(size);
    ret.resize(size, 0);
    let mut rng = rand::thread_rng();
    for x in ret.iter_mut() {
        *x = rng.gen();
    }
    ret
}

pub fn gen_random_bits(size: usize) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::with_capacity(size);
    ret.resize(size, 0);
    let mut rng = rand::thread_rng();
    for x in ret.iter_mut() {
        *x = if rng.gen() { 1 } else { 0 };
    }
    ret
}

pub fn elementwise_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(a.len());
    if a.len() != b.len() {
        panic!(
            "the two are not of the same length {}, {}",
            a.len(),
            b.len()
        );
    }
    for i in 0..a.len() {
        c.push(a[i] ^ b[i]);
    }
    c
}

pub fn elementwise_and(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(a.len());
    if a.len() != b.len() {
        panic!(
            "the two are not of the same length {}, {}",
            a.len(),
            b.len()
        );
    }
    for i in 0..a.len() {
        c.push(a[i] & b[i]);
    }
    c
}

pub fn bits2byte(a: &[u8]) -> u8 {
    let mut v = 0;
    let n = a.len();
    for i in 0..n {
        v = v << 1 | a[i];
    }
    v
}

pub fn byte2bits(a: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    for i in (0..8).rev() {
        let bv = 1 << i;
        v.push(if (a & bv) == bv { 1 } else { 0 });
    }
    v
}

pub fn bytes2bits(a: Vec<u8>) -> Vec<u8> {
    let n = a.len();
    let mut v = Vec::with_capacity(n * 8);
    for i in 0..n {
        v.extend_from_slice(&byte2bits(a[i]));
    }
    v
}

pub fn bits2bytes(a: &[u8]) -> Vec<u8> {
    let n = a.len() / 8;
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let s = i * 8;
        let e = (i + 1) * 8;
        let bits = &a[s..e];
        v.push(bits2byte(bits));
    }
    v
}

pub fn bytes2string(a: &[u8]) -> String {
    a.into_iter().map(|x| *x as char).collect()
}

pub fn bitwise_and(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!(
            "the two are not of the same length {}, {}",
            a.len(),
            b.len()
        );
    }
    let n = a.len() / 8;
    let d = elementwise_and(a, b);
    let mut c = Vec::with_capacity(n);
    for i in 0..n {
        let s = i * 8;
        let e = (i + 1) * 8;
        let bits = &d[s..e];
        c.push(bits2byte(bits));
        // println!("bits {:?} to byte {}", bits, c[i]);
    }
    c
}

pub fn sample_by_indices(idx: &[usize], values: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::with_capacity(idx.len());
    // res.resize(values.len(), 0);
    for &i in idx {
        // res[*i] = values[*i];
        res.push(values[i]);
    }
    res
}

pub fn pop32(barry: &[u8]) -> [u8; 32] {
    barry.try_into().expect("slice with incorrect length")
}

pub fn init_rand() -> (<Hc128Rng as SeedableRng>::Seed, Hc128Rng) {
    let mut seed: <Hc128Rng as SeedableRng>::Seed = Default::default();
    OsRng.fill_bytes(&mut seed);
    (seed, Hc128Rng::from_seed(pop32(&seed)))
}

pub fn get_rng(seed: &[u8]) -> Hc128Rng {
    Hc128Rng::from_seed(pop32(&seed))
}
