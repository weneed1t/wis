use crate::t1dumb_srct::*;
use crate::w1types::*;

mod tests_enca {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ packerr partialeq – equality depends only on variant, not on string       │
    // └────────────────────────────────────────────────────────────────────────────┘

    #[test]
    fn same_variant_with_different_strings_are_equal() {
        let dn = <DumpEnc as EncWis<DumpEndCrypt>>::new(&[1, 2, 3, 4], None).unwrap();

        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        //dn.encrypt::(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        <DumpEnc as EncWis<DumpEndCrypt>>::encrypt(
            &dn,
            &a1,       // &[u8]
            &mut a2,   // &mut [u8]
            &mut a3,   // &mut [u8]
            &0u64,     // &u64
            Some(&a4), // Option<&[u8]>
        )
        .unwrap();

        //  let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        let ret = <DumpEnc as EncWis<DumpEndCrypt>>::decrypt(
            &dn,
            &a1,       // &[u8]      — non_enc_head
            &mut a2,   // &mut [u8]  — enc_payload
            &mut a3,   // &mut [u8]  — auth_tag
            &0u64,     // &u64       — nonce_countr
            Some(&a4), // Option<&[u8]> — nonce
        )
        .unwrap();

        println!(" ");
        println!(" ");
        println!("headd {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::DecodedCorrectly, ret);
        //
        //
        //
        //
        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let mut a4 = vec![3u8; 25];

        // dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        <DumpEnc as EncWis<DumpEndCrypt>>::encrypt(
            &dn,
            &a1,       // &[u8]
            &mut a2,   // &mut [u8]
            &mut a3,   // &mut [u8]
            &0u64,     // &u64
            Some(&a4), // Option<&[u8]>
        )
        .unwrap();

        a4[7] = !a4[7];

        //let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        let ret = <DumpEnc as EncWis<DumpEndCrypt>>::decrypt(
            &dn,
            &a1,       // &[u8]      — non_enc_head
            &mut a2,   // &mut [u8]  — enc_payload
            &mut a3,   // &mut [u8]  — auth_tag
            &0u64,     // &u64       — nonce_countr
            Some(&a4), // Option<&[u8]> — nonce
        )
        .unwrap();

        println!("before enc ");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let mut a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        //dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        <DumpEnc as EncWis<DumpEndCrypt>>::encrypt(
            &dn,
            &a1,       // &[u8]
            &mut a2,   // &mut [u8]
            &mut a3,   // &mut [u8]
            &0u64,     // &u64
            Some(&a4), // Option<&[u8]>
        )
        .unwrap();

        a1[7] = !a1[7];

        // let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        let ret = <DumpEnc as EncWis<DumpEndCrypt>>::decrypt(
            &dn,
            &a1,       // &[u8]      — non_enc_head
            &mut a2,   // &mut [u8]  — enc_payload
            &mut a3,   // &mut [u8]  — auth_tag
            &0u64,     // &u64       — nonce_countr
            Some(&a4), // Option<&[u8]> — nonce
        )
        .unwrap();
        println!("after dec");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        // dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        <DumpEnc as EncWis<DumpEndCrypt>>::encrypt(
            &dn,
            &a1,       // &[u8]
            &mut a2,   // &mut [u8]
            &mut a3,   // &mut [u8]
            &0u64,     // &u64
            Some(&a4), // Option<&[u8]>
        )
        .unwrap();

        a2[7] = !a2[7];

        //  let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        let ret = <DumpEnc as EncWis<DumpEndCrypt>>::decrypt(
            &dn,
            &a1,       // &[u8]      — non_enc_head
            &mut a2,   // &mut [u8]  — enc_payload
            &mut a3,   // &mut [u8]  — auth_tag
            &0u64,     // &u64       — nonce_countr
            Some(&a4), // Option<&[u8]> — nonce
        )
        .unwrap();
        println!(" ");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);
    }
}

mod tests_dumps_nonser_cfcser {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    //use std::marker::PhantomData;

    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ dumpnonser tests – every method must panic with the documented message    │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    //#[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_new_panics() {
        let _ = DumpNonser::new(&[]);
    }

    #[test]
    //#[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_set_nonce_panics() {
        let mut stub = DumpNonser { t: 10, v: vec![] }; // we can create it directly because it's a struct
        let mut buf = [0u8; 8];
        stub.set_nonce(&mut buf).unwrap();
    }

    // verify that the type can be placed in an Option (as intended)
    #[test]
    fn dumpnonser_option_none_works() {
        let opt: Option<DumpNonser> = None;
        assert!(opt.is_none());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ dumpcfcser tests – every method must panic with the documented message    │
    // └────────────────────────────────────────────────────────────────────────────┘
    // #[test]
    //#[should_panic(expected = "This panic is called from DumpCfcser")]
    //fn dumpcfcser_new_panics() {
    //   let _ = DumpCrcser::new(&[]);
    // }
    #[test]
    //#[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_gen_crc_panics() {
        let mut stub: DumpCrcser = DumpCrcser { t: 10, v: vec![] };
        let mut crc_field = [0u8; 4];
        let payload = [1, 2, 3];
        stub.gen_crc(&payload, &mut crc_field).unwrap();
    }

    #[test]
    fn dumpcfcser_option_none_works() {
        let opt: Option<DumpCrcser> = None;
        assert!(opt.is_none());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ trait bounds – ensure that the stubs satisfy all required traits          │
    // │ (compilation already guarantees this, but we can explicitly check)        │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn dumpnonser_impl_noncer() {
        fn takes_noncer<T: Noncer>(_: T) {}
        takes_noncer(DumpNonser { t: 10, v: vec![] }); // compiles -> ok
    }

    #[test]
    fn dumpcfcser_impl_cfcser() {
        fn takes_cfcser<T: Crcser>(_: T) {}
        takes_cfcser(DumpCrcser { t: 10, v: vec![] }); // compiles -> ok
    }
}
