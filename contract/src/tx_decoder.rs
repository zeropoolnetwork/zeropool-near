use crate::{num::*, verifier::Proof};
use borsh::BorshDeserialize;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

// Sizes
const NUM_SIZE: usize = 32;
const PROOF_SIZE: usize = NUM_SIZE * 8;
const DELTA_SIZE: usize = 28;
const BALANCE_SIZE: usize = 8;
const ADDRESS_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const MEMO_META_SIZE: usize = 8;

// Offsets
// const SELECTOR: usize = 0;
const NULLIFIER: usize = 4;
const OUT_COMMIT: usize = NULLIFIER + NUM_SIZE;
const TRANSFER_INDEX: usize = OUT_COMMIT + NUM_SIZE;
const ENERGY_AMOUNT: usize = TRANSFER_INDEX + 6;
const TOKEN_AMOUNT: usize = ENERGY_AMOUNT + 14;
const TRANSACT_PROOF: usize = TOKEN_AMOUNT + 8;
const ROOT_AFTER: usize = TRANSACT_PROOF + PROOF_SIZE;
const TREE_PROOF: usize = ROOT_AFTER + NUM_SIZE;
const TX_TYPE: usize = TREE_PROOF + PROOF_SIZE;
const MEMO_SIZE: usize = TX_TYPE + 2;
const MEMO: usize = MEMO_SIZE + 2;
const MEMO_FEE: usize = MEMO;
const MEMO_NATIVE_AMOUNT: usize = MEMO_FEE + 8;
const MEMO_ADDRESS: usize = MEMO_NATIVE_AMOUNT + 8;

#[derive(Debug, PartialEq, Eq, BorshDeserialize, FromPrimitive)]
#[repr(u16)]
pub enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdraw = 2,
}
pub struct TxDecoder<'a> {
    data: &'a [u8],
}

impl<'a> TxDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        TxDecoder { data }
    }

    #[inline]
    pub fn nullifier(&self) -> U256 {
        U256::from_big_endian(&self.data[NULLIFIER..(NULLIFIER + NUM_SIZE)])
    }

    #[inline]
    pub fn nullifier_bytes(&self) -> &[u8] {
        &self.data[NULLIFIER..(NULLIFIER + NUM_SIZE)]
    }

    #[inline]
    pub fn out_commit(&self) -> U256 {
        U256::from_big_endian(&self.data[OUT_COMMIT..(OUT_COMMIT + NUM_SIZE)])
    }

    #[inline]
    pub fn transfer_index(&self) -> U256 {
        U256::from_big_endian(&self.data[TRANSFER_INDEX..(TRANSFER_INDEX + 6)])
    }

    #[inline]
    pub fn energy_amount(&self) -> U256 {
        let num = U256::from_big_endian(&self.data[ENERGY_AMOUNT..(ENERGY_AMOUNT + 14)]);
        ensure_twos_complement(num, 112)
    }

    #[inline]
    pub fn token_amount(&self) -> U256 {
        let num = U256::from_big_endian(&self.data[TOKEN_AMOUNT..(TOKEN_AMOUNT + 8)]);
        ensure_twos_complement(num, 64)
    }

    #[inline]
    pub fn delta(&self) -> U256 {
        let delta: [u8; DELTA_SIZE] = self.data[TRANSFER_INDEX..(TRANSFER_INDEX + DELTA_SIZE)]
            .try_into()
            .unwrap();
        U256::from_big_endian(&delta)
    }

    #[inline]
    pub fn transact_proof(&self) -> Proof {
        decode_proof(&self.data[TRANSACT_PROOF..(TRANSACT_PROOF + PROOF_SIZE)])
    }

    #[inline]
    pub fn root_after(&self) -> U256 {
        U256::from_big_endian(&self.data[ROOT_AFTER..(ROOT_AFTER + NUM_SIZE)])
    }

    #[inline]
    pub fn tree_proof(&self) -> Proof {
        decode_proof(&self.data[TREE_PROOF..(TREE_PROOF + PROOF_SIZE)])
    }

    #[inline]
    pub fn tx_type(&self) -> TxType {
        let bytes = self.data[TX_TYPE..(TX_TYPE + 2)].try_into().unwrap();
        let num = u16::from_be_bytes(bytes);
        TxType::from_u16(num).unwrap()
    }

    #[inline]
    pub fn memo_size(&self) -> usize {
        u16::from_be_bytes(self.data[MEMO_SIZE..(MEMO_SIZE + 2)].try_into().unwrap()) as usize
    }

    #[inline]
    pub fn memo_message(&self) -> &'a [u8] {
        &self.data[MEMO..(MEMO + self.memo_size())]
    }

    #[inline]
    pub fn memo_fee(&self) -> U256 {
        U256::from_big_endian(&self.data[MEMO_FEE..(MEMO_FEE + BALANCE_SIZE)])
    }

    #[inline]
    pub fn memo_native_amount(&self) -> U256 {
        U256::from_big_endian(&self.data[MEMO_NATIVE_AMOUNT..(MEMO_NATIVE_AMOUNT + BALANCE_SIZE)])
    }

    #[inline]
    pub fn memo_address(&self) -> &[u8] {
        &self.data[MEMO_ADDRESS..(MEMO_ADDRESS + ADDRESS_SIZE)]
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        let offset = if self.tx_type() == TxType::Withdraw {
            MEMO_ADDRESS + ADDRESS_SIZE
        } else {
            MEMO_FEE + BALANCE_SIZE
        };

        let data_size = offset - MEMO;

        &self.data[offset..(offset + self.memo_size() - data_size)]
    }

    #[inline]
    pub fn deposit_address(&self) -> &[u8] {
        let offset = MEMO + self.memo_size();
        &self.data[offset..(offset + ADDRESS_SIZE)]
    }

    #[inline]
    pub fn deposit_signature(&self) -> &[u8] {
        let offset = MEMO + self.memo_size() + ADDRESS_SIZE;
        &self.data[offset..(offset + SIGNATURE_SIZE)]
    }
}

fn ensure_twos_complement(n: U256, len: usize) -> U256 {
    let two_component_term = (U256::ONE.unchecked_shl(len as u32)).overflowing_neg().0;
    if n.unchecked_shr(len as u32 - 1) == U256::ZERO {
        n
    } else {
        n.unchecked_add(two_component_term)
    }
}

fn decode_proof(data: &[u8]) -> Proof {
    let a = decode_point(data);
    let b = decode_point(&data[NUM_SIZE * 2..]);
    let c = decode_point(&data[NUM_SIZE * 6..]);

    Proof { a, b, c }
}

fn decode_point<const N: usize>(data: &[u8]) -> [U256; N] {
    let mut buf = [U256::ZERO; N];

    for i in 0..N {
        let offset = i * NUM_SIZE;
        buf[i] = U256::from_big_endian(&data[offset..(offset + NUM_SIZE)]);
    }

    buf
}

/*


Transaction:
  selector: 00000000
  nullifier: 18135755683666780486705726096515581592937075413237525535764531312234702821216
  outCommit: 9875103410871285103361308081107134760380138017247206488459984883737397829316
  transferIndex: 0
  energyAmount: 0
  tokenAmount: 200000000
  txProof: {"a":["16153993334795621712865511689526273711033977936765637772168457421198340440933","821927861153260108133558743248645244350440871342947919333773207957701542123"],"b":[["18041074799956339989404127793325994068985684463869184035098939948189363535702","20952312370770275261689917049801139245643738556514580067423075659629050868846"],["1690974030569712234592473790126944952851436988593126781056395743116196118866","6875861533018175034326551595433480289800756245776660762039687155296190785191"]],"c":["17274062148274530341702866970920629027093422117531322563824769425786068791079","8682415130523778026830890275588450125599759282822507842063801645105043834151"]}
  rootAfter: 21652675626735987975169968181727654574547279479859946258417490477033531193891
  treeProof: {"a":["10686538254475776473216534947937754490129460791772711540918964568395263624374","4506832733573235221408001790449128164996641144557418008001938451723061840255"],"b":[["509804092863437081617046488569066659746032909371168924543051796293774402623","6037090826675945048351304940216848201874338398754937906858498581746011427156"],["20433495305786228606833411746089536856412745744617127166709936368043051299507","20872121501483526919200613019282138614955679091060661521372466598143188656253"]],"c":["8601720305977289843546629996137758183179863185849547732525217339065095979335","21281734457818870668013179201064660930839552115887700293028955685171575396120"]}
  txType: 0000
  memoSize: 210
  memoMessage: 000000000000000001000000fc46b984881594f536d90b247e0cded704dd5e5bbb7b1972f1e60604225fc82b08257ddfada8a9d6406b6692f19ce71d0d0a26f9dc0d4dc10fe122e6319d4227af97a65b0a22b5e6d0d968c5d6585a4c2093aeed6a2d54e74fc60731378ab0af4521f6c7229843de2c60aa9db9afea02269caad33a6c3e07a43358908073df76fc3ef452ce1f6f8651b01e8062e45990056227d15b39e05031b0ab104b2235ab70e0ff42190d263c291fef87e9c51742007e720a15469f728c65c74dec32e991667945130445
  depositSignature: d000ac5048ae858aca2e6aa43e00661562a47026fe88ff83992430204a15975256d45df220955c81b15ca644e935f6d009b10d20b15bfb970f3c0244d5e9bd6ad4b44c652695d8db6604aa51e94e61e3e353df0e34393634cafb825de0dfc48d

Transactoin data:
0x00000000281879554ace64fedf59ee5fd2c57b6d3a2b86a3ca0a263615c10a729a17d76015d51c471a4fdbd94cef4c5154749d8f974f4572aa443db906297985a7f41ec40000000000000000000000000000000000000000000000000bebc20023b6d6125b1aa4b2edb27e6532ed29acf7bd7ca401dfc54c7d131a4020f0c36501d131d6c7b54ee2a187cdbbf4aca95edd5f9143c2fb8b1985d42905a8c240eb27e2e2f0214e2a76c2417325bf6c373c553596419a45e613be739a367270ff562e5296ab2af862201df71a4214a432427aba147db80020030cf4d39c8f86346e03bd0eb0bf985f4053c7bf0fc89b6861c4d9ad95d22415f815412b8ae92d01520f339986e53ce76df9a243fc5b9a7edf8c590f5291226e9962e8c8eaa376e6a72630c5cfad67e5affa1141ec6f65bebc884ce2d4977574cf0bd6752d6167ef27133212a40cb2ccf22f675ea618207d222584867141253d1bd8bad6cd80ed85272fdefae822a2327ca2f4b90718cab6c65d2a9a599b7c01971fa6e0309b413a2317a05dc63b074571075861bba568f9134224e51eaa824aaffb67ffedb259c4b609f6c6e4f473d58581ee785b6aa3d51e26fcde22ba841eb1bbbd7e54fe58497f012089f4c4d9b2eb8830f23a0c1b9dcc12f8f0b35728d7bdf8bcd80f21b6e43f0d58df504401a79624ab21bace169b0a6ba9e48075280b25448eb782d6e951542d2cf2d0aec20a36f720bbe3d6603a69d94e6d9a37be0bbe09afaaf523cdb2b32e2533be83110a0d6704f5d42926b85fe50fe640a9bd96abecd00e9d278de07d130466b2a77c2cec08ee2b2cbed1b2b826f47c7aaf076ffeb3a0795bef7081472f0d08eb7b7d61573e2f117dc5aa1242ee277340b8d125276fe65abe90ec1718000000d2000000000000000001000000fc46b984881594f536d90b247e0cded704dd5e5bbb7b1972f1e60604225fc82b08257ddfada8a9d6406b6692f19ce71d0d0a26f9dc0d4dc10fe122e6319d4227af97a65b0a22b5e6d0d968c5d6585a4c2093aeed6a2d54e74fc60731378ab0af4521f6c7229843de2c60aa9db9afea02269caad33a6c3e07a43358908073df76fc3ef452ce1f6f8651b01e8062e45990056227d15b39e05031b0ab104b2235ab70e0ff42190d263c291fef87e9c51742007e720a15469f728c65c74dec32e991667945130445d000ac5048ae858aca2e6aa43e00661562a47026fe88ff83992430204a15975256d45df220955c81b15ca644e935f6d009b10d20b15bfb970f3c0244d5e9bd6ad4b44c652695d8db6604aa51e94e61e3e353df0e34393634cafb825de0dfc48d

 */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::num::U256;
    use core::str::FromStr;

    macro_rules! num {
        ($string:expr) => {
            U256::from_str($string).unwrap()
        };
    }

    #[test]
    fn test_ensure_twos_complement_positive() {
        let int: i64 = 123;
        let int_bytes = int.to_be_bytes();

        let uint = ensure_twos_complement(U256::from_big_endian(&int_bytes), 64);
        assert_eq!(uint, num!("123"));
    }

    #[test]
    fn test_ensure_twos_complement_negative() {
        let int: i64 = -123;
        let int_bytes = int.to_be_bytes();

        let uint = ensure_twos_complement(U256::from_big_endian(&int_bytes), 64);
        assert_eq!(uint.overflowing_neg().0, num!("123"));
    }

    #[test]
    fn test_tx_decoder() {
        let deposit_signature_block = hex_literal::hex!("d000ac5048ae858aca2e6aa43e00661562a47026fe88ff83992430204a15975256d45df220955c81b15ca644e935f6d009b10d20b15bfb970f3c0244d5e9bd6ad4b44c652695d8db6604aa51e94e61e3e353df0e34393634cafb825de0dfc48d");
        let data = hex_literal::hex!("00000000281879554ace64fedf59ee5fd2c57b6d3a2b86a3ca0a263615c10a729a17d76015d51c471a4fdbd94cef4c5154749d8f974f4572aa443db906297985a7f41ec40000000000000000000000000000000000000000000000000bebc20023b6d6125b1aa4b2edb27e6532ed29acf7bd7ca401dfc54c7d131a4020f0c36501d131d6c7b54ee2a187cdbbf4aca95edd5f9143c2fb8b1985d42905a8c240eb27e2e2f0214e2a76c2417325bf6c373c553596419a45e613be739a367270ff562e5296ab2af862201df71a4214a432427aba147db80020030cf4d39c8f86346e03bd0eb0bf985f4053c7bf0fc89b6861c4d9ad95d22415f815412b8ae92d01520f339986e53ce76df9a243fc5b9a7edf8c590f5291226e9962e8c8eaa376e6a72630c5cfad67e5affa1141ec6f65bebc884ce2d4977574cf0bd6752d6167ef27133212a40cb2ccf22f675ea618207d222584867141253d1bd8bad6cd80ed85272fdefae822a2327ca2f4b90718cab6c65d2a9a599b7c01971fa6e0309b413a2317a05dc63b074571075861bba568f9134224e51eaa824aaffb67ffedb259c4b609f6c6e4f473d58581ee785b6aa3d51e26fcde22ba841eb1bbbd7e54fe58497f012089f4c4d9b2eb8830f23a0c1b9dcc12f8f0b35728d7bdf8bcd80f21b6e43f0d58df504401a79624ab21bace169b0a6ba9e48075280b25448eb782d6e951542d2cf2d0aec20a36f720bbe3d6603a69d94e6d9a37be0bbe09afaaf523cdb2b32e2533be83110a0d6704f5d42926b85fe50fe640a9bd96abecd00e9d278de07d130466b2a77c2cec08ee2b2cbed1b2b826f47c7aaf076ffeb3a0795bef7081472f0d08eb7b7d61573e2f117dc5aa1242ee277340b8d125276fe65abe90ec1718000000d2000000000000000001000000fc46b984881594f536d90b247e0cded704dd5e5bbb7b1972f1e60604225fc82b08257ddfada8a9d6406b6692f19ce71d0d0a26f9dc0d4dc10fe122e6319d4227af97a65b0a22b5e6d0d968c5d6585a4c2093aeed6a2d54e74fc60731378ab0af4521f6c7229843de2c60aa9db9afea02269caad33a6c3e07a43358908073df76fc3ef452ce1f6f8651b01e8062e45990056227d15b39e05031b0ab104b2235ab70e0ff42190d263c291fef87e9c51742007e720a15469f728c65c74dec32e991667945130445d000ac5048ae858aca2e6aa43e00661562a47026fe88ff83992430204a15975256d45df220955c81b15ca644e935f6d009b10d20b15bfb970f3c0244d5e9bd6ad4b44c652695d8db6604aa51e94e61e3e353df0e34393634cafb825de0dfc48d");
        let decoder = TxDecoder::new(&data);

        assert_eq!(
            decoder.nullifier(),
            num!("18135755683666780486705726096515581592937075413237525535764531312234702821216"),
            "nullifier",
        );

        assert_eq!(
            decoder.out_commit(),
            num!("9875103410871285103361308081107134760380138017247206488459984883737397829316"),
            "out_commit",
        );

        assert_eq!(decoder.transfer_index(), num!("0"), "transfer_index");

        assert_eq!(decoder.energy_amount(), num!("0"), "energy_amount");

        assert_eq!(decoder.token_amount(), num!("200000000"), "token_amount");

        assert_eq!(
            decoder.transact_proof(),
            Proof {
                a: [
                    num!("16153993334795621712865511689526273711033977936765637772168457421198340440933"),
                    num!("821927861153260108133558743248645244350440871342947919333773207957701542123"),
                ],
                b: [
                    num!("18041074799956339989404127793325994068985684463869184035098939948189363535702"),
                    num!("20952312370770275261689917049801139245643738556514580067423075659629050868846"),
                    num!("1690974030569712234592473790126944952851436988593126781056395743116196118866"),
                    num!("6875861533018175034326551595433480289800756245776660762039687155296190785191"),
                ],
                c: [
                    num!("17274062148274530341702866970920629027093422117531322563824769425786068791079"),
                    num!("8682415130523778026830890275588450125599759282822507842063801645105043834151"),
                ]
            },
            "transact_proof",
        );

        assert_eq!(
            decoder.root_after(),
            num!("21652675626735987975169968181727654574547279479859946258417490477033531193891"),
            "root_after"
        );

        assert_eq!(
            decoder.tree_proof(),
            Proof {
                a: [
                    num!("10686538254475776473216534947937754490129460791772711540918964568395263624374"),
                    num!("4506832733573235221408001790449128164996641144557418008001938451723061840255"),
                ],
                b: [
                    num!("509804092863437081617046488569066659746032909371168924543051796293774402623"),
                    num!("6037090826675945048351304940216848201874338398754937906858498581746011427156"),
                    num!("20433495305786228606833411746089536856412745744617127166709936368043051299507"),
                    num!("20872121501483526919200613019282138614955679091060661521372466598143188656253"),
                ],
                c: [
                    num!("8601720305977289843546629996137758183179863185849547732525217339065095979335"),
                    num!("21281734457818870668013179201064660930839552115887700293028955685171575396120"),
                ]
            },
            "tree_proof",
        );

        assert_eq!(decoder.tx_type(), TxType::Deposit, "tx_type");

        assert_eq!(decoder.memo_size(), 210, "memo_size");

        assert_eq!(
            decoder.memo_message(),
            hex_literal::hex!("000000000000000001000000fc46b984881594f536d90b247e0cded704dd5e5bbb7b1972f1e60604225fc82b08257ddfada8a9d6406b6692f19ce71d0d0a26f9dc0d4dc10fe122e6319d4227af97a65b0a22b5e6d0d968c5d6585a4c2093aeed6a2d54e74fc60731378ab0af4521f6c7229843de2c60aa9db9afea02269caad33a6c3e07a43358908073df76fc3ef452ce1f6f8651b01e8062e45990056227d15b39e05031b0ab104b2235ab70e0ff42190d263c291fef87e9c51742007e720a15469f728c65c74dec32e991667945130445"),
            "memo_message",
        );

        assert_eq!(
            decoder.deposit_signature(),
            &deposit_signature_block[32..],
            "deposit_signature",
        );

        assert_eq!(
            decoder.deposit_address(),
            &deposit_signature_block[0..32],
            "deposit_address",
        )
    }

    #[test]
    fn test_tx_decoder_decode_point() {
        use core::str::FromStr;

        let num1 = U256::from_str(
            "11533315366764172207830942257467815827048793486992167376211289220451677858288",
        )
        .unwrap();

        let num2 = U256::from_str(
            "9051134181781801742358171403867869806562829238281402507597064540637910203283",
        )
        .unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&num1.to_big_endian());
        data.extend_from_slice(&num2.to_big_endian());

        let [other1, other2] = decode_point(&data);

        assert_eq!(other1, num1);
        assert_eq!(other2, num2);
    }
}
