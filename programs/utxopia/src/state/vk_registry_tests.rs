use super::*;

#[test]
fn test_joinsplit_public_inputs() {
    assert_eq!(joinsplit_num_public_inputs(1, 2), 5); // root + bound + 1 null + 2 comm
    assert_eq!(joinsplit_num_public_inputs(2, 2), 6);
    assert_eq!(joinsplit_num_public_inputs(1, 1), 4);
}

#[test]
fn test_vk_registry_size() {
    assert_eq!(VkRegistry::SIZE, 1060);
}

#[test]
fn test_vk_registry_set_vk_roundtrip() {
    let mut buf = [0u8; VkRegistry::SIZE];
    let registry = VkRegistry::init(&mut buf).unwrap();
    registry.n_inputs = 1;
    registry.n_outputs = 2;

    let delta = [2u8; 128];
    let ic = [[3u8; 64]; 6];
    let hash = compute_vk_hash(&delta, &ic);
    registry.set_vk(&hash, &delta, &ic).unwrap();

    assert_eq!(registry.get_vk_hash(), &hash);
    assert_eq!(registry.get_delta_g2(), &delta);
    assert_eq!(registry.get_ic().unwrap(), &ic);
}

/// The point of recomputing the hash: material that does not match the submitted identity is
/// refused, instead of being stored under a hash that says it is something else.
#[test]
fn set_vk_rejects_a_hash_that_does_not_cover_the_material() {
    let mut buf = [0u8; VkRegistry::SIZE];
    let registry = VkRegistry::init(&mut buf).unwrap();
    registry.n_inputs = 1;
    registry.n_outputs = 2;

    let delta = [2u8; 128];
    let ic = [[3u8; 64]; 6];

    assert!(registry.set_vk(&[0u8; 32], &delta, &ic).is_err());

    // A hash computed over *different* delta is equally refused — the binding covers every
    // field, not just the IC points.
    let other = compute_vk_hash(&[9u8; 128], &ic);
    assert!(registry.set_vk(&other, &delta, &ic).is_err());

    // Nothing was written by the rejected calls.
    assert_eq!(registry.ic_len, 0);
    assert_eq!(registry.get_vk_hash(), &[0u8; 32]);
}

/// The hash must depend on every input, or it cannot distinguish two different keys.
#[test]
fn vk_hash_covers_delta_and_every_ic_point() {
    let delta = [2u8; 128];
    let ic = [[3u8; 64]; 6];
    let base = compute_vk_hash(&delta, &ic);

    let mut other_delta = delta;
    other_delta[0] ^= 1;
    assert_ne!(compute_vk_hash(&other_delta, &ic), base);

    for i in 0..ic.len() {
        let mut other_ic = ic;
        other_ic[i][63] ^= 1;
        assert_ne!(compute_vk_hash(&delta, &other_ic), base, "IC[{i}] not covered");
    }

    // Length is part of the preimage too: a shorter IC list is a different key.
    assert_ne!(compute_vk_hash(&delta, &ic[..5]), base);
}

/// Cross-implementation pin. The bytes are the real `joinsplit_1x2.vkey.json` (delta and the six
/// IC points, in on-chain storage order) and the digest is what the SDK's `computeVkHash`
/// produces from that same file. If the two preimages ever drift apart — a coordinate order
/// changed on one side, a field added or dropped — every VK registration starts failing on
/// chain, so the divergence has to fail here first.
#[test]
fn vk_hash_matches_the_sdk_for_a_real_circuit() {
    use hex_literal::hex;

    let delta = hex!(
        "01a7f20ccb56974c71a6cafc55e7a3b02470535a92cf21d28f3e8419a6a077e2"
        "0ada613bbe2ef34d9676e60e502bcf1f652bb533fa2a7bad7eb443df3c788052"
        "16e27e958a02ca2a53da9e6a7047c7796078d91112844807fcf946582b5ea428"
        "2644611fc4ed57e112f4c4721e1cd775e4b72090af660940d2349ce480c98427"
    );
    let ic = [
        hex!("274a928c6c0f2fddacc3f9780121969450cc9be58bb8671eecf22bb1e80cff0e"
             "2d54cbb3cb06c9dd45fc1f57f32fa92372a0c6e86d24e9ef2bd7cdd61c7f4d65"),
        hex!("2463a0787b53ab520093d34e70ed59959b9a27c621d0e6cc66f0239ee23a2ae1"
             "03bc2838ab8b6d9e2123d9dd62c4dcf4336e4d02760fe197efecfae748d29522"),
        hex!("0cfc3ca1dfcb091ace338c9fab2b66ef976425084bf5d814d4eb1e48cbc6cb58"
             "20301b3bff03bee5d7f09eb8b31e4ff0beadb90a1477ebe77375547a65edf156"),
        hex!("209767b681e2e1148869143aa336fc91e1259d271934c594201c2a1bc1fa4be4"
             "0d7d2a4b2e21f979c5d40c5d5c14616615e0b1ae730a229d087e4fe7a2b8a284"),
        hex!("29e37f26b66bbfbb7304d987017d8d2cae74c3c879db96a4a740ca1efd38d073"
             "08fd7ae3f6198acb79e46b6e73dd1b08fc6abd6cd0cecf1a78c4112172c4eb31"),
        hex!("2de2c56bd35a4bc6c3f0363221163c8bbfe2d3bed9775f46356164a8ec5837f2"
             "25697fff706ef9856456fb5e210921c46b5499c83612c65629814747cd72e827"),
    ];

    assert_eq!(
        compute_vk_hash(&delta, &ic),
        hex!("f59d2992131ecd6c481f6d02a58aab179370732ad7b93dd834c91d316f4d488c")
    );

    // And the shape lines up: JoinSplit(1,2) has 5 public inputs, so 6 IC points.
    let mut buf = [0u8; VkRegistry::SIZE];
    let registry = VkRegistry::init(&mut buf).unwrap();
    registry.n_inputs = 1;
    registry.n_outputs = 2;
    registry
        .set_vk(&compute_vk_hash(&delta, &ic), &delta, &ic)
        .unwrap();
}
