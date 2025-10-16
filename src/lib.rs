pub mod t10_api;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
pub mod t1mt_hasttab;
pub mod t1pology;
pub mod t1queue_tcpudp;
pub mod t2router;
pub mod t3conn;
pub mod wutils; //utils //topology

use mambo_map::Mambo;
use std::{
    sync::{Arc, Mutex},
    thread,
};
#[test]
fn based_example() {
    const NUM_THREADS: usize = 10;
    const OPS_PER_THREAD: usize = 10;
    let mut std_handles = Vec::new();
    let shift = 1_000_000u64;
    let global_counter = Arc::new(Mutex::new(0usize));
    //=======================================================================
    //The number of shards, a shard is an independent piece of the hash table,
    //the optimal number of shards = the number of threads.
    let shards = 16;
    /*elements that are added to the hash table
    A hash table has a data storage topology
    Arc<(f32, Box<[(Mutex<u32>, RwLock<(Mutex<usize>, [Box<[Mutex<(bool, Vec<(T, u64)>)>]>; 2])>)]>)>.
    Each individual Mutex can have an average of 1.0 to 10.0 elements.
    the more elements there are in the Mutex, the lower the overhead of storing in memory per element,
    but the higher the chance that one thread will block another when reading one element.*/
    let elems_in_mutex = 7.0;
    //returns Err(&str) if the data is incorrect
    let mut mambo = Mambo::<String>::new(shards, elems_in_mutex).unwrap();

    for tt in 1..NUM_THREADS {
        let mut mambo_arc = mambo.arc_clone();
        let arc_global_counter = Arc::clone(&global_counter);
        std_handles.push(thread::spawn(move || {
            for key in 0..OPS_PER_THREAD {
                let key = (tt + (key * OPS_PER_THREAD * 10)) + shift as usize;

                let elem_me = format!("mambo elem {}", key);

                /*to insert an element, if an element with the same key value already exists,
                it will return Some(T.clone())
                false indicates whether it is necessary to forcibly replace the element with a new one,
                 even if there is already an element with such a key*/
                assert_eq!(mambo_arc.insert(key as u64, &elem_me, false), None);

                assert_eq!(
                    mambo_arc.insert(key as u64, &elem_me, false),
                    Some(elem_me.clone())
                );
                /*reading, because the Mutex is kept open during reading,
                as long as there is an active read operation in the shard,
                a resizing operation and a filter operation cannot be applied to the shard.*/
                //NEVER CALL A RECURSIVE READ INSIDE A read() CLOSURE, AS THIS MAY LEAD TO MUTUAL LOCKING!!
                mambo_arc.read(key as u64, |ind| {
                    let ind = ind.unwrap();

                    assert_eq!(
                        ind.clone(),
                        elem_me,
                        " non eq read  key: {}   rea: {}   in map: {}",
                        key,
                        elem_me,
                        ind.clone()
                    );
                });

                let key_to_filter = {
                    let mut mutexer = arc_global_counter.lock().unwrap();
                    let key_to_filter = *mutexer;
                    *mutexer += 1;
                    key_to_filter
                };
                let elem_me = format!(
                    "elem {} {} theread: {}{}",
                    key_to_filter,
                    if key_to_filter > 9 { "" } else { " " },
                    tt,
                    if tt > 9 { "" } else { " " },
                );
                assert_eq!(
                    mambo_arc.insert(key_to_filter as u64, &elem_me, false),
                    None
                );
            }

            for key in 0..OPS_PER_THREAD {
                let key = tt + (key * OPS_PER_THREAD * 10) + shift as usize;
                let elem_me = format!("mambo elem {}", key);
                //deleting an element, if such an element exists,
                // it will be deleted from the table and returned as (T.clone())
                assert_eq!(mambo_arc.remove(key as u64), Some(elem_me.clone()));
            }
        }));
    }

    for handle in std_handles {
        handle.join().unwrap();
    }

    println!("before filter:");
    mambo.filter(|mut_elem, key_u64| {
            /*The filter option is needed when you need to filter out all the elements in the hashtable
            or change them, passes a closure with the desired parameters RFy: FnMut(&mut T, u64) -> bool,
            where &mut T is an element and u64 is its key.bool is a decision to delete an item or not,
            if bool == true, then this item will not be deleted from the cache table. if bool ==  false,
            then the element will be deleted*/
            println!(
                "    elem: {}, {} key: {}",
                *mut_elem,
                if key_u64 > 9 { "" } else { " " },
                key_u64
            );

            *mut_elem += " is even";
            /*an example that leaves in the table only those elements that are divisible by 2 without remainder*/
            if 0 == key_u64 % 2 {
                return true;
            }
            false
        });

    println!("after filter: ");
    mambo.filter(|mut_elem, key_u64| {
        println!(
            "    elem: {:<28}, {} key: {}",
            *mut_elem,
            if key_u64 > 9 { "" } else { " " },
            key_u64
        );

        true
    });
}
