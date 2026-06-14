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

        let hash = [1u8; 32];
        let delta = [2u8; 128];
        let ic = [[3u8; 64]; 6];
        registry.set_vk(&hash, &delta, &ic).unwrap();

        assert_eq!(registry.get_vk_hash(), &hash);
        assert_eq!(registry.get_delta_g2(), &delta);
        assert_eq!(registry.get_ic().unwrap(), &ic);
    }
