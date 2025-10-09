use std::fmt::Debug;

#[derive(Debug)]
pub enum WSQueueState {
    ElemIdIsBig,
    ElemIdIsSmall,
    ElemIsAlreadyIn,
    SuccessfulInsertion,
}

impl PartialEq for WSQueueState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (WSQueueState::ElemIdIsBig, WSQueueState::ElemIdIsBig) => true,
            (WSQueueState::ElemIdIsSmall, WSQueueState::ElemIdIsSmall) => true,
            (WSQueueState::ElemIsAlreadyIn, WSQueueState::ElemIsAlreadyIn) => true,
            (WSQueueState::SuccessfulInsertion, WSQueueState::SuccessfulInsertion) => true,
            _ => false,
        }
    }
}

pub struct WSQueue<T> {
    in_queue: usize,
    k_mod: usize,
    last_give_num: usize,
    data: Box<[Option<(usize, T)>]>,
    was_get_queue: bool,
}

impl<T: Copy + Debug> WSQueue<T> {
    pub fn new(sizecap: usize) -> Result<Self, &'static str> {
        if sizecap == 0 {
            return Err("sizecap must be greater than zero");
        }
        Ok(WSQueue {
            in_queue: 0,
            k_mod: 0,
            last_give_num: 0,
            data: vec![None; sizecap].into_boxed_slice(),
            was_get_queue: false,
        })
    }

    pub fn insert(&mut self, item: (usize, T)) -> WSQueueState {
        if item.0 < self.last_give_num {
            return WSQueueState::ElemIdIsSmall;
        }

        let pos = (item.0 - self.last_give_num) - self.was_get_queue as usize;

        if pos >= self.data.len() {
            return WSQueueState::ElemIdIsBig;
        }

        let elem_url = &mut self.data[(pos + self.k_mod) % self.data.len()];

        if elem_url.is_some() {
            return WSQueueState::ElemIsAlreadyIn;
        }

        *elem_url = Some(item);

        self.in_queue += 1;

        //self.state(); //==============================================12432143256576765?==========================================================
        WSQueueState::SuccessfulInsertion
    }

    fn k_add(&mut self, addin: usize) {
        self.k_mod = (self.k_mod + addin) % self.data.len();
    }

    fn edit_my_state(&mut self, size_of_ret: usize, last_item_num: usize) {
        let le = self.data.len();
        for x in self.k_mod..size_of_ret + self.k_mod {
            self.data[x % le] = None;
        }

        self.in_queue = match self.in_queue.checked_sub(size_of_ret) {
            Some(new_in) => new_in,
            None => {
                panic!(
                    r#"fatal error in pub fn get_queue().
                       function pub fn get_queue wants to
                       return more elements than it has,
                       can't be handled via Result<>, Sorry~~"#
                );
            }
        };

        self.k_add(size_of_ret);

        self.last_give_num = last_item_num;
    }

    pub fn get_queue(&mut self) -> Box<[(usize, T)]> {
        let copied_slice: Box<[(usize, T)]> = self
            .data
            .iter()
            .cycle()
            .skip(self.k_mod)
            .take(self.data.len())
            .take_while(|opt| opt.is_some())
            .map(|opt| opt.as_ref().unwrap().clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        self.edit_my_state(
            copied_slice.len(),
            match copied_slice.last() {
                Some(x) => x.0,

                _ => {
                    return vec![].into_boxed_slice();
                }
            },
        );

        self.was_get_queue = true;
        //self.state(); //==============================================12432143256576765?==========================================================

        copied_slice
    }

    pub fn how_items_in_queue(&self) -> usize {
        self.in_queue
    }
    pub fn last_num_get(&self) -> usize {
        self.last_give_num
    }
}

pub struct WuniversaQueue {
    size_of_buf: usize,
    type_of_queue: bool,
}

// debug time~!

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_work_subsequence() {
        let mut xx: WSQueue<u32> = WSQueue::new(50).unwrap();

        let mut xxx = 0_usize;
        for _ in 0..30_usize {
            for az in 0..50usize {
                let _ = xx.insert((xxx + (az + 17) % 50, 0));

                if az % 5 == 0 {
                    assert_eq!(
                        xx.insert((xxx + (az + 17) % 50, 0)),
                        WSQueueState::ElemIsAlreadyIn
                    );
                }

                if az % 11 == 0 && az > 60 {
                    assert_eq!(
                        xx.insert((xxx + (az + 17) % 10, 0)),
                        WSQueueState::ElemIsAlreadyIn
                    );
                }
            }
            xxx += 50;

            let tempo = xx.get_queue().to_vec();

            //println!("{:?}",tempo.iter().map(|x|{x.0}).collect::<Vec<usize>>());
            let mut t = tempo.first().unwrap().0;
            println!("tempo.len() = {:?}", tempo.len());
            for l in tempo.iter().skip(1) {
                assert!(l.0 > t, "> l.0 = {} is not greater than t = {}", l.0, t);
                assert!(l.0 - 1 == t, "==tempo[{}].0 is not greater than {}", l.0, t);
                t = l.0;
                //println!("l.0 = {}", l.0);
            }
        }
    }

    #[test]
    fn test_segment() {
        let mut xx: WSQueue<u32> = WSQueue::new(50).unwrap();

        for x in 1..1000_usize {
            let _ = xx.insert((x - 1, 0));

            if x > 1 && x % 13 == 0 {
                let bw = xx.how_items_in_queue();

                let geu = xx.get_queue();
                assert_eq!(geu.len(), 13);
                assert_eq!(geu.len(), bw);
                //println!("geulen:{}",geu.len());
            }
        }
    }

    #[test]
    fn test_kmod() {
        let mut xx: WSQueue<u32> = WSQueue::new(123).unwrap();

        xx.k_mod = 100;

        xx.k_add(70);
        assert_eq!(xx.k_mod, (100 + 70) % 123);

        xx.k_add(1000);
        assert_eq!(xx.k_mod, (100 + 70 + 1000) % 123);

        xx.k_add(3);
        assert_eq!(xx.k_mod, (100 + 70 + 1000 + 3) % 123);
    }

    #[test]
    fn test_hands() {
        let mut xx: WSQueue<f32> = WSQueue::new(8).unwrap();

        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((7, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((8, 0.0)), WSQueueState::ElemIdIsBig); //8
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::ElemIsAlreadyIn); //9
        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //10

        assert_eq!(xx.in_queue, 8);

        assert_eq!(
            xx.get_queue(),
            (vec![
                (0, 0.0),
                (1, 0.0),
                (2, 0.0),
                (3, 0.0),
                (4, 0.0),
                (5, 0.0),
                (6, 0.0),
                (7, 0.0)
            ])
            .into_boxed_slice()
        );

        assert_eq!(xx.insert((9, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((11, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((12, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

        assert_eq!(xx.insert((10, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((13, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

        assert_eq!(xx.insert((8, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (8, 0.0),
                (9, 0.0),
                (10, 0.0),
                (11, 0.0),
                (12, 0.0),
                (13, 0.0)
            ])
            .into_boxed_slice()
        );

        assert_eq!(xx.insert((22, 0.0)), WSQueueState::ElemIdIsBig);
        assert_eq!(xx.insert((21, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::ElemIdIsSmall);
        assert_eq!(xx.insert((14, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![(14, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((15, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((16, 0.0)), WSQueueState::SuccessfulInsertion);

        assert_eq!(xx.insert((17, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((18, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((19, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((20, 0.0)), WSQueueState::SuccessfulInsertion);

        assert_eq!(
            xx.get_queue(),
            (vec![
                (15, 0.0),
                (16, 0.0),
                (17, 0.0),
                (18, 0.0),
                (19, 0.0),
                (20, 0.0),
                (21, 0.0)
            ])
            .into_boxed_slice()
        );

        let mut xx: WSQueue<f32> = WSQueue::new(7).unwrap();

        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.in_queue, 7);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (0, 0.0),
                (1, 0.0),
                (2, 0.0),
                (3, 0.0),
                (4, 0.0),
                (5, 0.0),
                (6, 0.0)
            ])
            .into_boxed_slice()
        );

        let mut xx: WSQueue<f32> = WSQueue::new(7).unwrap();

        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(0, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.in_queue, 1);
        assert_eq!(
            xx.get_queue(),
            (vec![(1, 0.0)]).into_boxed_slice(),
            "{:?}",
            xx.data
        );

        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3

        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(2, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(3, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((7, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((8, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((9, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((10, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((11, 0.0)), WSQueueState::ElemIdIsBig); //6
        assert_eq!(xx.in_queue, 7);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (4, 0.0),
                (5, 0.0),
                (6, 0.0),
                (7, 0.0),
                (8, 0.0),
                (9, 0.0),
                (10, 0.0)
            ])
            .into_boxed_slice()
        );
    }
}
