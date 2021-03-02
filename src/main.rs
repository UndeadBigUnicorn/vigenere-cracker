use std::{collections::HashMap, fs::read_to_string, vec::Vec};

const CHARACTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MAX_KEY_LENGTH: i32 = 32;
const ENGLISH_IC: f64 = 1.73;
const A: u8 = 'A' as u8;

fn uppercase_and_filter(input: &str) -> Vec<u8> {
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut result = Vec::new();

    for c in input.chars() {
        // Ignore anything that is not in our short list of chars. We can then safely cast to u8.
        if alphabet.iter().any(|&x| x as char == c) {
            result.push(c.to_ascii_uppercase() as u8);
        }
    }

    return result;
}

fn vigenere(key: &str, text: &str, is_encoding: bool) -> String {
    let key_bytes = uppercase_and_filter(key);
    let text_bytes = uppercase_and_filter(text);

    let mut result_bytes = Vec::new();

    for (i, c) in text_bytes.iter().enumerate() {
        let c2 = if is_encoding {
            (c + key_bytes[i % key_bytes.len()] - 2 * A) % 26 + A
        } else {
            (c + 26 - key_bytes[i % key_bytes.len()]) % 26 + A
        };
        result_bytes.push(c2);
    }

    String::from_utf8(result_bytes).unwrap()
}

// count the frequency of each letter
fn count_letter_freq(cipher_text: &str) -> Vec<i32> {
    let mut letter_freqs: Vec<i32> = vec![0; 26];
    for i in 0..=25 {
        let c = (A + i as u8) as char;
        letter_freqs[i] = cipher_text.matches(c).count() as i32;
    }
    return letter_freqs;
}

// calcuate index of concedence
fn index_of_coincidence(cipher_text: &str) -> f64 {
    let text_length = cipher_text.len() as f64 - 1.0;
    let total_letters = 26;
    let letter_freq = count_letter_freq(cipher_text);

    let divider = (text_length * (text_length - 1.0)) / total_letters as f64;
    let n_sum = letter_freq
        .iter()
        .fold(0.0f64, |sum, val| sum + (val * (val - 1)) as f64);

    if divider == 0.0 {
        return divider;
    }

    return n_sum / divider;
}

// determine possible key length
fn possible_key_length(cipher_text: &str) -> Vec<u32> {
    let mut possible_keys: Vec<f64> = Vec::new();
    let mut key_lens = Vec::new();

    for i in 1..=MAX_KEY_LENGTH as u32 {
        let mut ic = 0.0;
        for j in 0..i as u32 {
            let mut buffer = String::new();
            for k in 0..cipher_text.len() as u32 - 1 {
                if k % i == j {
                    buffer.push_str(&cipher_text.chars().nth(k as usize).unwrap().to_string());
                }
            }
            ic += index_of_coincidence(&buffer);
        }
        let average_ic = ic / i as f64;
        possible_keys.push(average_ic);
    }

    for (index, key) in possible_keys.iter().enumerate() {
        if key - ENGLISH_IC < 0.20 {
            key_lens.push((index + 1) as u32);
        }
    }

    return key_lens;
}

// split ciphertext with given length and transpose text
fn transpose(cipher_text: &str, key_length: u32) -> Vec<String> {
    let mut substrings = Vec::new();

    for index in 0..key_length {
        let mut substring = String::new();
        for i in (index..cipher_text.len() as u32 - 1).step_by(key_length as usize) {
            substring.push_str(&cipher_text.chars().nth(i as usize).unwrap().to_string())
        }
        substrings.push(substring);
    }

    return substrings;
}

fn guess_key(substrings: Vec<String>) -> String {
    let mut key = String::new();
    let english_freq: HashMap<String, f64> = [
        ("A".to_string(), 8.167),
        ("B".to_string(), 1.492),
        ("C".to_string(), 2.782),
        ("D".to_string(), 4.253),
        ("E".to_string(), 12.702),
        ("F".to_string(), 2.228),
        ("G".to_string(), 2.015),
        ("H".to_string(), 6.094),
        ("I".to_string(), 6.966),
        ("J".to_string(), 0.153),
        ("K".to_string(), 0.772),
        ("L".to_string(), 4.025),
        ("M".to_string(), 2.406),
        ("N".to_string(), 6.749),
        ("O".to_string(), 7.507),
        ("P".to_string(), 1.929),
        ("Q".to_string(), 0.095),
        ("R".to_string(), 5.987),
        ("S".to_string(), 6.327),
        ("T".to_string(), 9.056),
        ("U".to_string(), 2.758),
        ("V".to_string(), 0.978),
        ("W".to_string(), 2.361),
        ("X".to_string(), 0.150),
        ("Y".to_string(), 1.974),
        ("Z".to_string(), 0.074),
    ]
    .iter()
    .cloned()
    .collect();

    for text in substrings {
        let mut scores: Vec<f64> = Vec::new();

        for letter in CHARACTERS.chars() {
            //score to determine the most possible letter as a key
            let mut letter_freq_score = 0.0;
            let decrypt_msg = vigenere(&letter.to_string(), &text, false);
            let letter_freqs = count_letter_freq(&decrypt_msg);
            for i in 0..26 {
                let letter_index = ((i as u8 + A) as char).to_string();
                letter_freq_score +=
                    letter_freqs[i] as f64 * english_freq.get(&letter_index).unwrap();
            }
            scores.push(letter_freq_score);
        }

        // find the biggest freq socre in score slice
        let mut biggest = scores.first().unwrap();
        let mut letter = String::new();
        for (index, v) in scores.iter().enumerate() {
            if v >= biggest {
                biggest = v;
                letter = ((index as u8 + A) as char).to_string();
            }
        }

        println!("The biggest score is {} ===> {}", biggest, letter);

        key.push_str(&letter);
    }

    return key;
}

fn main() {
    let cryptogram = &read_to_string("message.txt").unwrap();
    for length in possible_key_length(cryptogram) {
        let substring = transpose(cryptogram, length);
        let possible_key = guess_key(substring);
        let decrypt_message = vigenere(&possible_key, cryptogram, false);
        println!("-----------------------------------");
        println!("Length: {}", length);
        println!("Key: {}", possible_key);
        println!("Message: {}", decrypt_message);
        println!("-----------------------------------");
    }

    println!("-----------------------------------");
    let small_cryptogram = &read_to_string("small_message.txt").unwrap();
    println!("Original Message: {}", small_cryptogram);
    let key = "bit";
    println!("Key: {}", key);
    let decrypt_message = vigenere(key, small_cryptogram, false);
    println!("Decrypted Message: {}", decrypt_message);
    println!("-----------------------------------");
}
