use std::env;
use colored::Colorize;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

fn get_position_key(position: usize) -> u8 {((position * 23 + 42) % 256) as u8}

fn encrypt_data_simple(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    
    for (position, &byte) in data.iter().enumerate() {
        let key = get_position_key(position);
        let xored = byte ^ key;
        let substituted = SBOX[xored as usize];
        let rotated = substituted.rotate_left((position % 8) as u32);
        
        result.push(rotated);
    }
    result
}

fn execute_massive_dead_code_for_correct_char(seed: u8) -> u64 {
    let mut result = seed as u64;
    for i in 0..10000 {
        result = result.wrapping_mul(0x5851f42d4c957f2d);
        result ^= (i * seed as usize) as u64;
        result = result.rotate_left(13);
        
        for j in 0..100 {
            let idx = ((result >> (j % 64)) & 0xFF) as usize;
            result ^= SBOX[idx] as u64;
        }
        
        for k in 0..128 {
            if result & (1 << (k % 64)) != 0 {
                result ^= 1 << ((k ^ 7) % 64);
            }
        }
        
        for m in 0..512 {
            let val = SBOX[m % 256];
            result ^= (val as u64) << (m % 64);
        }
    }
    
    for mega_round in 0..500 {
        for byte_pos in 0..8 {
            let byte_val = ((result >> (byte_pos * 8)) & 0xFF) as u8;
            let encrypted = SBOX[byte_val as usize];
            result ^= (encrypted as u64) << (byte_pos * 8);
        }
        
        result = result.rotate_left((mega_round % 64) as u32);
        
        for nested in 0..50 {
            result ^= SBOX[(nested + mega_round) % 256] as u64;
            result = result.wrapping_mul(0x9e3779b97f4a7c15);
        }
    }
    
    for ultra_round in 0..2000 {
        for cascade in 0..16 {
            let byte_val = ((result >> (cascade * 4)) & 0xFF) as u8;
            result ^= SBOX[byte_val as usize] as u64;
        }
        
        for extra in 0..10 {
            result = result.wrapping_add(SBOX[(extra * ultra_round) % 256] as u64);
        }
    }
    
    result
}

fn compare_single_byte(user_byte: u8, correct_byte: u8, position: usize) -> bool {
    if user_byte == correct_byte {
        let explosion_result = execute_massive_dead_code_for_correct_char(user_byte);
        println!("Input length: {} bytes", explosion_result);
        
        let mut accumulated = 0u64;
        for i in 0..5000 {
            accumulated = accumulated.wrapping_add(SBOX[i % 256] as u64);
            accumulated ^= (position as u64).rotate_left((i % 64) as u32);
            
            let transformed = SBOX[((accumulated ^ i as u64) & 0xFF) as usize];
            accumulated = accumulated.wrapping_mul(transformed as u64);
            
            for k in 0..20 {
                let val = SBOX[(k * 17 + i) % 256];
                accumulated ^= (val as u64).rotate_left((k % 64) as u32);
            }
        }
        
        for _round in 0..1000 {
            for row in 0..4 {
                for col in 0..4 {
                    let temp_val = SBOX[((accumulated >> (row * 4 + col)) & 0xFF) as usize];
                    accumulated ^= temp_val as u64;
                    
                    for inner in 0..10 {
                        accumulated = accumulated.wrapping_add(SBOX[(inner * row + col) % 256] as u64);
                    }
                }
            }
        }
        
        std::hint::black_box(accumulated);
        
        true
    } else {
        false
    }
}

fn verify_flag(user_input: &str, correct_encrypted: &[u8]) -> bool {
    let user_encrypted = encrypt_data_simple(user_input.as_bytes());
    
    if user_encrypted.len() != correct_encrypted.len() {
        return false;
    }
    
    for i in 0..user_encrypted.len() {
        if !compare_single_byte(user_encrypted[i], correct_encrypted[i], i) {
            return false;
        }
    }
    
    true
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: {} <flag_guess>", args[0]);
        std::process::exit(1);
    }
    
    let user_flag = &args[1];

    println!("{}", "RPMA certificate (Rust Professional Malware Analysist) exam v1.1".cyan().bold());
    println!("{}", "================================================================".cyan().bold());
    println!("{}", "Can you crack this ransomware key and submit it to us?".yellow());   
    
    if user_flag.len() != 49 {
        println!("❌ Length mismatch!");
        return;
    }
    
    const CORRECT_ENCRYPTED: &[u8] = &[
        0x51, 0x6c, 0x97, 0x1b, 0x52, 0x16, 0x6f, 0x36, 0xee, 0xfc, 0xf7, 0xd0, 0x7d, 0xec, 0x9d, 0xf4, 
        0xe4, 0x3d, 0x90, 0x76, 0x8b, 0x00, 0x08, 0x9d, 0xef, 0x49, 0xfe, 0x41, 0x1a, 0x8b, 0xe6, 0xe6, 
        0xe2, 0x58, 0x16, 0x66, 0xd7, 0x2b, 0xc7, 0xee, 0x8c, 0x0f, 0x06, 0x1a, 0xcc, 0x8f, 0xa4, 0xe2, 
        0xc5
    ];

    if verify_flag(user_flag, &CORRECT_ENCRYPTED) {
        println!("{}", "Good flag! c:".green());
    } else {
        println!("{}", "Incorrect flag :c".red());
    }   
}
