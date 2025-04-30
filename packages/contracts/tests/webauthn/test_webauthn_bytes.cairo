use argent::utils::bytes::{
    SpanU8TryIntoFelt252, SpanU8TryIntoU256, ByteArrayExt, u8s_to_u32s_pad_end, u32s_to_u8s, u256_to_u8s
};

#[test]
fn convert_bytes_to_u256_fit_128() {
    let bytes = array![84, 153, 96, 222, 88, 128, 232, 198, 135, 67, 65, 112];
    let value = bytes.span().try_into().unwrap();
    assert_eq!(value, 0x549960de5880e8c687434170_u256, "invalid");
}

#[test]
fn convert_bytes_to_u256_fit_256() {
    let bytes = array![
        73,
        150,
        13,
        229,
        136,
        14,
        140,
        104,
        116,
        52,
        23,
        15,
        100,
        118,
        96,
        91,
        143,
        228,
        174,
        185,
        162,
        134,
        50,
        199,
        153,
        92,
        243,
        186,
        131,
        29,
        151,
        99,
    ];
    let value = bytes.span().try_into().unwrap(); // sha256("localhost")
    assert_eq!(value, 0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763_u256, "invalid");
}

#[test]
fn convert_bytes_to_felt252_overflow() {
    let bytes = array![
        73,
        150,
        13,
        229,
        136,
        14,
        140,
        104,
        116,
        52,
        23,
        15,
        100,
        118,
        96,
        91,
        143,
        228,
        174,
        185,
        162,
        134,
        50,
        199,
        153,
        92,
        243,
        186,
        131,
        29,
        151,
        99,
    ];
    let output: Option<felt252> = bytes.span().try_into(); // sha256("localhost")
    assert!(output.is_none(), "invalid");
}

#[test]
fn convert_bytes_to_felt252() {
    let bytes = array![222, 173, 190, 239,];
    let value: felt252 = bytes.span().try_into().unwrap();
    assert_eq!(value, 0xdeadbeef, "invalid");

    let bytes = array![
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
        222,
        173,
        190,
        239,
    ];
    let value: felt252 = bytes.span().try_into().unwrap();
    assert_eq!(value, 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef, "invalid");
}

#[test]
fn convert_bytes_to_max_felt252() {
    // 0x08000000000000110000000000000000000000000000000000000000000000000
    let bytes = array![
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x11,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    let value: felt252 = bytes.span().try_into().unwrap();
    assert_eq!(value, -1, "invalid");
}

#[test]
fn convert_u8s_to_u32s_pad_end() {
    let input = "localhost".into_bytes();
    let output = u8s_to_u32s_pad_end(input.span());
    let expected = array!['loca', 'lhos', 't\x00\x00\x00'];
    assert_eq!(output, expected, "invalid");

    let input = "localhost:".into_bytes();
    let output = u8s_to_u32s_pad_end(input.span());
    let expected = array!['loca', 'lhos', 't:\x00\x00'];
    assert_eq!(output, expected, "invalid");

    let input = "localhost:6".into_bytes();
    let output = u8s_to_u32s_pad_end(input.span());
    let expected = array!['loca', 'lhos', 't:6\x00'];
    assert_eq!(output, expected, "invalid");

    let input = "localhost:69".into_bytes();
    let output = u8s_to_u32s_pad_end(input.span());
    let expected = array!['loca', 'lhos', 't:69'];
    assert_eq!(output, expected, "invalid");
}

#[test]
fn convert_u32s_to_u8s() {
    let input = array![0x6a09e667, 0xbb67ae85].span();
    let output = u32s_to_u8s(input);
    let expected = array![0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85].span();
    assert_eq!(output, expected, "invalid");
}

#[test]
fn convert_u256_to_u8s() {
    let input = 0x06fd6673287ba2e4d2975ad878dc26c0a989c549259d87a044a8d37bb9168bb4;
    let output = u256_to_u8s(input);
    let expected = array![
        0x06,
        0xfd,
        0x66,
        0x73,
        0x28,
        0x7b,
        0xa2,
        0xe4,
        0xd2,
        0x97,
        0x5a,
        0xd8,
        0x78,
        0xdc,
        0x26,
        0xc0,
        0xa9,
        0x89,
        0xc5,
        0x49,
        0x25,
        0x9d,
        0x87,
        0xa0,
        0x44,
        0xa8,
        0xd3,
        0x7b,
        0xb9,
        0x16,
        0x8b,
        0xb4,
    ];
    assert_eq!(output, expected, "invalid");
}
