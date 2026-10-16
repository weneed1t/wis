use crate::t0grouper::GroupTopology;

use crate::w1types::*;

mod tests_my_role {
    #![allow(clippy::as_conversions)]
    use super::*;

    #[test]
    fn test_is_initiator() {
        assert!(MyRole::Initiator.is_initiator());
        assert!(!MyRole::Passive.is_initiator());
    }

    #[test]
    fn test_is_passive() {
        assert!(MyRole::Passive.is_passive());
        assert!(!MyRole::Initiator.is_passive());
    }

    #[test]
    fn test_state_to_bit() {
        assert_eq!(MyRole::Passive.sate_to_bit(), 0);
        assert_eq!(MyRole::Initiator.sate_to_bit(), 1);
    }

    #[test]
    fn test_bit_to_state() {
        assert!(matches!(MyRole::bit_to_state(0), MyRole::Passive));
        assert!(matches!(MyRole::bit_to_state(1), MyRole::Initiator));
        assert!(matches!(MyRole::bit_to_state(2), MyRole::Passive)); // 2 & 1 = 0
        assert!(matches!(MyRole::bit_to_state(3), MyRole::Initiator)); // 3 & 1 = 1
        assert!(matches!(MyRole::bit_to_state(255), MyRole::Initiator)); // 255 & 1 = 1
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(MyRole::Initiator, MyRole::Initiator);
        assert_eq!(MyRole::Passive, MyRole::Passive);
        assert_ne!(MyRole::Initiator, MyRole::Passive);
        assert_ne!(MyRole::Passive, MyRole::Initiator);
    }

    #[test]
    fn test_clone() {
        let role1 = MyRole::Initiator;
        let role2 = role1;
        assert_eq!(role1, role2);

        let role3 = MyRole::Passive;
        let role4 = role3;
        assert_eq!(role3, role4);
    }

    #[test]
    fn test_debug() {
        let initiator = format!("{:?}", MyRole::Initiator);
        let passive = format!("{:?}", MyRole::Passive);

        assert!(initiator.contains("Initiator"));
        assert!(passive.contains("Passive"));
    }

    #[test]
    fn test_roundtrip_conversion() {
        // Test that bit_to_state is the inverse of state_to_bit
        for role in [MyRole::Initiator, MyRole::Passive] {
            let bit = role.sate_to_bit();
            let reconstructed = MyRole::bit_to_state(bit);
            assert_eq!(role, reconstructed);
        }
    }
}

mod tests_my_type {
    #![allow(clippy::as_conversions)]
    use super::*;

    #[test]
    fn test_is_data() {
        assert!(PackType::Data.is_data());
        assert!(!PackType::Fback.is_data());
    }

    #[test]
    fn test_is_fback() {
        assert!(PackType::Fback.is_fback());
        assert!(!PackType::Data.is_fback());
    }

    #[test]
    fn test_sate_to_bit() {
        assert_eq!(PackType::Fback.sate_to_bit(), 1);
        assert_eq!(PackType::Data.sate_to_bit(), 0);
    }

    #[test]
    fn test_bit_to_state() {
        assert!(matches!(PackType::bit_to_state(0), PackType::Data));
        assert!(matches!(PackType::bit_to_state(1), PackType::Fback));
        // Test with higher bits (only LSB should matter)
        assert!(matches!(PackType::bit_to_state(2), PackType::Data)); // 2 & 1 = 0
        assert!(matches!(PackType::bit_to_state(3), PackType::Fback)); // 3 & 1 = 1
        assert!(matches!(PackType::bit_to_state(255), PackType::Fback)); // 255 & 1 = 1
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(PackType::Data, PackType::Data);
        assert_eq!(PackType::Fback, PackType::Fback);
        assert_ne!(PackType::Data, PackType::Fback);
        assert_ne!(PackType::Fback, PackType::Data);
    }

    #[test]
    fn test_clone() {
        let data = PackType::Data;
        let cloned = data;
        assert_eq!(data, cloned);

        let fback = PackType::Fback;
        let cloned_fback = fback;
        assert_eq!(fback, cloned_fback);
    }
}

mod tests_statusdecrypt {
    #![allow(clippy::as_conversions)]
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 1: creation & debug/clone traits (auto-derived)                     │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn debug_and_clone_work() {
        let original = StatusDecrypt::DecodedCorrectly;
        let cloned = original.clone();
        assert!(format!("{:?}", cloned).contains("DecodedCorrectly"));
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 2: equality (PartialEq) – both variants compare correctly          │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn decoded_correctly_equals_itself() {
        assert_eq!(
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::DecodedCorrectly
        );
    }

    #[test]
    fn package_damaged_equals_itself() {
        assert_eq!(StatusDecrypt::PackageDamaged, StatusDecrypt::PackageDamaged);
    }

    #[test]
    fn different_variants_are_not_equal() {
        assert_ne!(
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::PackageDamaged
        );
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 3: helper methods (is_correctly / is_damaged) – one test per variant│
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn is_correctly_returns_true_only_for_decoded_correctly() {
        assert!(StatusDecrypt::DecodedCorrectly.is_correctly());
        assert!(!StatusDecrypt::PackageDamaged.is_correctly());
    }

    #[test]
    fn is_damaged_returns_true_only_for_package_damaged() {
        assert!(StatusDecrypt::PackageDamaged.is_damaged());
        assert!(!StatusDecrypt::DecodedCorrectly.is_damaged());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 4: exhaustive coverage – one test verifies all discriminant values  │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn all_variants_covered() {
        // this test ensures we haven't missed any variant if the enum grows
        let variants = [
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::PackageDamaged,
        ];
        for v in variants {
            match v {
                StatusDecrypt::DecodedCorrectly => assert!(v.is_correctly()),
                StatusDecrypt::PackageDamaged => assert!(v.is_damaged()),
            }
        }
    }
}

/*

mod tests_pack_err {
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ packerr partialeq – equality depends only on variant, not on string       │
    // └────────────────────────────────────────────────────────────────────────────┘

    #[test]
    fn same_variant_with_different_strings_are_equal() {
        // any two strings inside the same variant compare as equal
        assert_eq!(PackErr::IdConnErr("a"), PackErr::IdConnErr("b"));
        assert_eq!(PackErr::IdSendRecvErr("x"), PackErr::IdSendRecvErr("y"));
        assert_eq!(PackErr::CrcErr("foo"), PackErr::CrcErr("bar"));
        assert_eq!(PackErr::TagErr("1"), PackErr::TagErr("2"));
        assert_eq!(PackErr::LenErr("short"), PackErr::LenErr("long"));
        assert_eq!(PackErr::UndefinedErr("?"), PackErr::UndefinedErr("!"));
        assert_eq!(PackErr::TTLErr("127"), PackErr::TTLErr("255"));
    }

    #[test]
    fn same_variant_with_identical_strings_are_equal() {
        // sanity check – identical strings are obviously equal
        assert_eq!(PackErr::IdConnErr("same"), PackErr::IdConnErr("same"));
    }

    #[test]
    fn different_variants_are_not_equal() {
        // every pair of different variants must compare as not equal
        let all_variants = [
            PackErr::IdConnErr(""),
            PackErr::IdSendRecvErr(""),
            PackErr::CrcErr(""),
            PackErr::TagErr(""),
            PackErr::LenErr(""),
            PackErr::UndefinedErr(""),
            PackErr::TTLErr(""),
        ];

        for (i, a) in all_variants.iter().enumerate() {
            for (j, b) in all_variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "same variant {:?} should equal itself", a);
                } else {
                    assert_ne!(
                        a, b,
                        "different variants {:?} and {:?} must not be equal",
                        a, b
                    );
                }
            }
        }
    }

    #[test]
    fn equality_is_symmetric() {
        let a = PackErr::CrcErr("left");
        let b = PackErr::CrcErr("right");
        assert_eq!(a, b);
        assert_eq!(b, a); // symmetry property
    }

    #[test]
    fn equality_is_transitive() {
        let a = PackErr::TagErr("first");
        let b = PackErr::TagErr("second");
        let c = PackErr::TagErr("third");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c); // transitivity holds because all are same variant
    }

    #[test]
    fn equality_with_self_always_true() {
        let err = PackErr::LenErr("self");
        assert_eq!(err, err); // reflexivity
    }
}
*/

//_! Implementation of RSA encryption algorithm using only the Rust standard library.
//_! For demonstration purposes only – not secure for real-world use.
//_! Assumes availability of trusted prime numbers (obtained externally).
//_! Uses u64 for all values; intermediate multiplications use u128 to avoid overflow.

/// Structure representing an RSA key pair.

pub struct RsaTest {
    n: u64, // modulus (product of p and q)
    e: u64, // public exponent (usually 65537)
    d: u64, // private exponent
}

impl RsaTest {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    /// Creates a new RSA instance from two prime numbers `p` and `q`.
    /// The public exponent `e` is fixed to 65537.
    /// Returns `Err` if the provided primes are invalid (e.g., equal, or (p-1)*(q-1) not
    /// coprime with e).
    pub fn new(p: u64, q: u64) -> Result<Self, String> {
        if p == q {
            return Err("p and q must be different".to_string());
        }
        let n = p * q;
        let phi = (p - 1) * (q - 1); // Euler's totient

        // Commonly used public exponent
        let e = 65537;

        // Ensure e is coprime with phi
        if Self::gcd(phi, e) != 1 {
            return Err("e and φ(n) are not coprime".to_string());
        }

        // Compute private exponent d = e⁻¹ mod φ(n)
        let d = match Self::mod_inv(e, phi) {
            Some(val) => val,
            None => return Err("modular inverse not found".to_string()),
        };

        Ok(Self { n, e, d })
    }

    /// Encrypts a plaintext message `m` (must be less than `n`).
    /// Returns ciphertext.
    pub fn encrypt(e: u64, n: u64, m: u64) -> u64 {
        Self::mod_pow(m, e, n)
    }

    /// Decrypts a ciphertext `c` (must be less than `n`).
    /// Returns plaintext.
    pub fn decrypt(&self, c: u64) -> u64 {
        Self::mod_pow(c, self.d, self.n)
    }
    ///
    pub fn get_e(&self) -> u64 {
        self.e
    }
    ///
    pub fn get_n(&self) -> u64 {
        self.n
    }

    // ---------- helper functions ----------

    /// Modular exponentiation: (base^exp) % modulus using exponentiation by squaring.
    fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        if modulus == 1 {
            return 0;
        }
        let mut result = 1;
        base %= modulus;
        while exp > 0 {
            if exp % 2 == 1 {
                result = ((result as u128) * (base as u128) % (modulus as u128)) as u64;
            }
            base = ((base as u128) * (base as u128) % (modulus as u128)) as u64;
            exp >>= 1;
        }
        result
    }

    /// Computes the greatest common divisor of two numbers.
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    /// Computes the modular inverse of `a` modulo `m` using the extended Euclidean
    /// algorithm. Returns `Some(inverse)` if exists, else `None`.
    fn mod_inv(a: u64, m: u64) -> Option<u64> {
        let (mut t, mut new_t) = (0i64, 1i64);
        let (mut r, mut new_r) = (m as i64, a as i64);
        while new_r != 0 {
            let quotient = r / new_r;
            (t, new_t) = (new_t, t - quotient * new_t);
            (r, new_r) = (new_r, r - quotient * new_r);
        }
        if r > 1 {
            return None; // not invertible
        }
        if t < 0 {
            t += m as i64;
        }
        Some(t as u64)
    }
}

mod tests_rsa {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_rsa_encrypt_decrypt() {
        // Two small primes (for demonstration only – use much larger ones in practice)
        let p = 8811653;
        let q = 9539867;
        let rsa = RsaTest::new(p, q).unwrap();
        let eee = rsa.get_e();
        let nnn = rsa.get_n();
        //
        //
        //
        let message = 123456;
        let cipher = RsaTest::encrypt(eee, nnn, message);

        let plain = rsa.decrypt(cipher);
        assert_eq!(message, plain);
    }

    #[test]
    fn test_invalid_primes() {
        assert!(RsaTest::new(61, 61).is_err()); // equal primes
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(RsaTest::mod_pow(4, 13, 497), 445); // known example
    }
}

mod test_for_hand_maker_tester {
    use super::*;
    use crate::t1dumb_srct::{DumpEndCrypt, DumpHandMaker};

    #[test]
    fn t1_() {
        assert_eq!(
            hand_maker_tester::<DumpHandMaker<DumpEndCrypt>, DumpEndCrypt>(),
            Ok(())
        );
    }
}
mod tests_atomic_files {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestEnd;
    impl EndCryptStuctor for TestEnd {
        fn get_symmetric_key_byte_vec(&self) -> Box<[u8]> {
            Box::new([])
        }
        fn new() -> Self {
            Self
        }
        fn set_symmetric_key_byte_vec(&mut self, _data: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    type File = AtomHandFile<TestEnd>;

    #[test]
    fn test_is_initiator() {
        let init = File::InitiatorFileSize(42);
        let pass = File::PassiveFileSize(100);
        assert!(init.is_initiator());
        assert!(!pass.is_initiator());
    }

    #[test]
    fn test_is_passive() {
        let init = File::InitiatorFileSize(42);
        let pass = File::PassiveFileSize(100);
        assert!(pass.is_passive());
        assert!(!init.is_passive());
    }

    #[test]
    fn test_size() {
        assert_eq!(File::InitiatorFileSize(42).size(), 42);
        assert_eq!(File::PassiveFileSize(100).size(), 100);
    }

    #[test]
    fn test_partial_eq() {
        let a = File::InitiatorFileSize(10);
        let b = File::InitiatorFileSize(10);
        let c = File::InitiatorFileSize(20);
        let d = File::PassiveFileSize(10);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(c, d);
    }
}

mod tests_headbytestruct {
    use super::*;

    #[test]
    fn test_combinations() {
        let mut h = HeadByteStruct::new();

        for i in 0..255 {
            h.set_reserve_7(i & (1 << 7) > 0);
            h.set_reserve_6(i & (1 << 6) > 0);
            h.set_reserve_5(i & (1 << 5) > 0);
            h.set_reserve_4(i & (1 << 4) > 0);
            h.set_reserve_3(i & (1 << 3) > 0);
            h.set_is_kill(i & (1 << 2) > 0);
            h.set_need_trim_is_pad(i & (1 << 1) > 0);
            h.set_is_fake(i & (1 << 0) > 0);

            assert_eq!(h.to_byte(), i);

            assert_eq!(h.reserve_7(), (i & (1 << 7) > 0));
            assert_eq!(h.reserve_6(), (i & (1 << 6) > 0));
            assert_eq!(h.reserve_5(), (i & (1 << 5) > 0));
            assert_eq!(h.reserve_4(), (i & (1 << 4) > 0));
            assert_eq!(h.reserve_3(), (i & (1 << 3) > 0));
            assert_eq!(h.is_kill(), (i & (1 << 2) > 0));
            assert_eq!(h.need_trim(), (i & (1 << 1) > 0));
            assert_eq!(h.is_fake(), (i & (1 << 0) > 0));

            assert_eq!(h, HeadByteStruct::from_byte(i))
        }
    }
}

mod tests_wis_err {
    use super::*;

    #[test]
    fn test_is_critical() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Low disk space");
        let critical: WisErr<&str, i32> = WisErr::Critical(500);

        assert!(!warning.is_critical());
        assert!(critical.is_critical());
    }

    #[test]
    fn test_is_warning() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Low disk space");
        let critical: WisErr<&str, i32> = WisErr::Critical(500);

        assert!(warning.is_warning());
        assert!(!critical.is_warning());
    }

    #[test]
    fn test_partial_eq_same_variants() {
        let warn1: WisErr<&str, i32> = WisErr::Warning("Timeout");
        let warn2: WisErr<&str, i32> = WisErr::Warning("Timeout");
        let warn3: WisErr<&str, i32> = WisErr::Warning("Connection lost");

        let crit1: WisErr<&str, i32> = WisErr::Critical(404);
        let crit2: WisErr<&str, i32> = WisErr::Critical(404);
        let crit3: WisErr<&str, i32> = WisErr::Critical(500);

        assert_eq!(warn1, warn2);
        assert_eq!(crit1, crit2);

        assert_ne!(warn1, warn3);
        assert_ne!(crit1, crit3);
    }

    #[test]
    fn test_partial_eq_different_variants() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Database error");
        let critical: WisErr<&str, i32> = WisErr::Critical(101);
        assert_ne!(warning, critical);
    }
}

mod test_ttl {
    use super::*;

    #[test]

    fn test_ttl_initialization_and_getters() {
        #![allow(clippy::unwrap_used)]
        let ttl = Ttl::new(64, -2, 128, true);

        assert_eq!(ttl, Err("max <= start".to_string()));

        let ttl = Ttl::new(64, -2, 64, true);
        assert_eq!(ttl, Err("max <= start".to_string()));

        let ttl = Ttl::new(1000, -1, 0, true);
        assert_eq!(ttl, Err("start == 0".to_string()));

        let ttl = Ttl::new(0, -1, 1, true);
        assert_eq!(ttl, Err("max == 0".to_string()));

        let ttl = Ttl::new(65, 0, 64, true);
        assert_eq!(ttl, Err("ttl_edit == 0".to_string()));

        let ttl = Ttl::new(65, -2, 64, true).unwrap();

        assert_eq!(ttl.max(), 65);
        assert_eq!(ttl.edit(), -2);
        assert_eq!(ttl.start(), 64);
        assert!(ttl.forced_pruning());
        //
        let ttl = Ttl::new(65, -2, 64, false).unwrap();
        assert!(!ttl.forced_pruning());
    }
}

mod test_pack_sheme {

    use super::*;
    use crate::t0pology::*;
    use crate::w1types::PackTypeGroup as PF;

    #[test]
    fn main() {
        #![allow(clippy::unwrap_used)]
        let f1 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(1),
        ];
        let f2 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(2),
        ];
        let f3 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(3),
        ];

        let bx: [(Box<[PackFields]>, PF, u8); 3] = [
            (Box::new(f1.clone()), PF::Any, 1_u8),
            (Box::new(f2), PF::Any, 2_u8),
            (Box::new(f3), PF::Any, 3_u8),
        ];

        let p1 = PackTopology::new(10, &f1, true, false).unwrap();

        let mo = PackScheme::OnePack(p1.clone());

        let mg = PackScheme::GroupPack(GroupTopology::new(&bx, 10, true, false).unwrap());

        assert!(mo.is_one());
        assert!(!mo.is_group());
        assert!(mg.is_group());
        assert!(!mg.is_one());

        for i in 0..10 {
            assert_eq!(*mo.get_topol(i, PF::Any).unwrap(), p1);
        }

        let t1 = mg
            .get_topol(1, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;

        let t2 = mg
            .get_topol(2, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;

        let t3 = mg
            .get_topol(3, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
    }
}
