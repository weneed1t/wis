//use std::collections::HashMap;

pub struct MTu64Hash {}

impl MTu64Hash {
    pub fn new() {
        //let a =HashMap::
    }
}

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};

// 1. Определяем наш кастомный хэшер для u64
#[derive(Default)]
struct IdentityHasher {
    hash: u64,
}

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        // Преобразуем байты обратно в u64
        self.hash = u64::from_ne_bytes(bytes.try_into().unwrap());
    }

    fn write_u64(&mut self, i: u64) {
        self.hash = i;
        println!("is-Me{}", i);
    }
}

// 2. Определяем BuildHasher - фабрику для нашего хэшера
#[derive(Default)]
struct IdentityBuildHasher;

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher::default()
    }
}
#[test]
fn main1() {
    // 3. Создаем HashMap с нашей кастомной хэш-функцией
    let mut map: HashMap<u64, &str, IdentityBuildHasher> =
        HashMap::with_hasher(IdentityBuildHasher);

    // Вставляем значения (явно указываем тип u64)
    map.insert(123u64, "value1");
    map.insert(456u64, "value2");
    map.insert(789u64, "value3");

    // Проверяем работу
    println!("Value for key 123: {:?}", map.get(&123u64)); // Some("value1")
    println!("Value for key 456: {:?}", map.get(&456u64)); // Some("value2")

    // 4. Демонстрируем работу identity hashing
    let mut hasher = IdentityBuildHasher.build_hasher();
    121u64.hash(&mut hasher); // Явно указываем тип u64
    println!("Hash for key 123 is: {}", hasher.finish()); // 123

    let mut hasher = IdentityBuildHasher.build_hasher();
    456u64.hash(&mut hasher); // Явно указываем тип u64
    println!("Hash for key 456 is: {}", hasher.finish()); // 456

    // 5. Показываем содержимое HashMap
    println!("\nFull map contents: {:?}", map);
}

// ⚠️ ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ:
// Этот IdentityHasher крайне уязвим к HashDoS-атакам!
// Используйте только в полностью контролируемых environments.
// Для production-кода используйте проверенные крейты:
//
// use ahash::RandomState; // Быстро и защищено
// let mut map = HashMap::<u64, &str, RandomState>::with_hasher(RandomState::new());
//
// Или для максимальной скорости (без защиты):
// use rustc_hash::FxHashMap;
// let mut map = FxHashMap::<u64, &str>::default();

use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
struct ThreadSafeCounter {
    inner: Arc<Mutex<i32>>,
}

impl ThreadSafeCounter {
    // Конструктор
    fn new(initial_value: i32) -> Self {
        ThreadSafeCounter {
            inner: Arc::new(Mutex::new(initial_value)),
        }
    }

    // Метод для инкремента
    fn increment(&self) -> i32 {
        let mut value = self.inner.lock().unwrap();
        *value += 1;
        *value
    }

    // Метод для получения значения
    fn get(&self) -> i32 {
        *self.inner.lock().unwrap()
    }

    // Создание копии для использования в других потоках
    fn clone_for_thread(&self) -> Self {
        ThreadSafeCounter {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Реализуем Clone для удобства
impl Clone for ThreadSafeCounter {
    fn clone(&self) -> Self {
        self.clone_for_thread()
    }
}
#[test]
fn m2ain() {
    let counter = ThreadSafeCounter::new(0);

    let mut handles = vec![];

    for i in 0..1000 {
        // Просто клонируем структуру!
        let counter_clone = counter.clone();

        let handle = thread::spawn(move || {
            for xxx in 0..100_000 {
                let new_value = counter_clone.increment();
                if xxx % 20000 == 0 {
                    println!("Thread {}: value = {}", i, new_value);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Final value: {}", counter.get());
}
