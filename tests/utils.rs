pub mod constants;
extern crate fuzzy_extractor;

use fuzzy_extractor::utils::*;


#[cfg(test)]
mod tests {
    use rand::Rng;
    use super::*;

    #[test]
    fn utils_byte2bits() {
        let bits = byte2bits(10);
        assert_eq!(bits, vec![0, 0, 0, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn utils_bytes2bits() {
        let bits = bytes2bits(vec![1, 10]);
        assert_eq!(bits, [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn utils_bits2byte() {
        let byte = bits2byte(&[0, 0, 0, 0, 1, 0, 1, 0]);
        assert_eq!(byte, 10);
    }

    #[test]
    fn utils_bits2bytes() {
        let byte = bits2bytes(&vec![0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(byte, [10, 1]);
    }

    #[test]
    fn utils_rng() {
        let (seed, mut rng) = init_rand();
        let rand_nums: Vec<usize> = (0..20000)
            .map(|_| {
                rng.gen()
            })
            .collect();
        let mut reproduced_rng = get_rng(&seed);
        let reproduced_rand_nums: Vec<usize> = (0..20000).map(|_| {reproduced_rng.gen()}).collect();
        assert_eq!(rand_nums, reproduced_rand_nums);
    }
}
