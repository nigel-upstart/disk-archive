//! Ghost model and inverse proof for the production key encoder.
use vstd::prelude::*;

verus! {
pub open spec fn plain(byte: u8) -> bool {
    (48 <= byte <= 57) || (65 <= byte <= 90) || (97 <= byte <= 122)
        || byte == 45 || byte == 95 || byte == 46 || byte == 47
}

pub open spec fn digit(value: int) -> u8 {
    if value < 10 { (48 + value) as u8 } else { (55 + value) as u8 }
}

pub open spec fn undigit(byte: u8) -> int {
    if 48 <= byte <= 57 { byte as int - 48 } else { byte as int - 55 }
}

pub open spec fn encoded_byte(byte: u8) -> Seq<u8> {
    if plain(byte) { seq![byte] } else { seq![37u8, digit(byte as int / 16), digit(byte as int % 16)] }
}

pub open spec fn encoded(bytes: Seq<u8>) -> Seq<u8>
    decreases bytes.len(),
{
    if bytes.len() == 0 { Seq::empty() }
    else { encoded_byte(bytes[0]) + encoded(bytes.drop_first()) }
}

pub open spec fn decoded(bytes: Seq<u8>) -> Seq<u8>
    decreases bytes.len(),
{
    if bytes.len() == 0 { Seq::empty() }
    else if bytes[0] == 37 {
        if bytes.len() < 3 { Seq::empty() }
        else { seq![((undigit(bytes[1]) * 16 + undigit(bytes[2])) as u8)] + decoded(bytes.subrange(3, bytes.len() as int)) }
    } else { seq![bytes[0]] + decoded(bytes.drop_first()) }
}

pub open spec fn key(prefix: Seq<u8>, bytes: Seq<u8>) -> Seq<u8> {
    prefix + seq![47u8, 118u8, 49u8, 47u8] + encoded(bytes) + seq![46u8, 103u8, 122u8]
}

pub proof fn encoded_push(bytes: Seq<u8>, byte: u8)
    ensures encoded(bytes.push(byte)) == encoded(bytes) + encoded_byte(byte),
    decreases bytes.len(),
{
    reveal_with_fuel(encoded, 2);
    if bytes.len() > 0 {
        encoded_push(bytes.drop_first(), byte);
        assert(bytes.push(byte).drop_first() =~= bytes.drop_first().push(byte));
    } else {
        assert(bytes =~= Seq::<u8>::empty());
        assert(bytes.push(byte) =~= seq![byte]);
    }
    assert(encoded(bytes.push(byte)) =~= encoded(bytes) + encoded_byte(byte));
}

pub proof fn round_trip(bytes: Seq<u8>)
    ensures decoded(encoded(bytes)) == bytes,
    decreases bytes.len(),
{
    if bytes.len() > 0 {
        let byte = bytes[0];
        let rest = bytes.drop_first();
        round_trip(rest);
        if plain(byte) {
            assert(byte != 37);
            assert(encoded(bytes).drop_first() =~= encoded(rest));
        } else {
            assert(0 <= byte as int / 16 < 16);
            assert(0 <= byte as int % 16 < 16);
            assert(undigit(digit(byte as int / 16)) == byte as int / 16);
            assert(undigit(digit(byte as int % 16)) == byte as int % 16);
            assert((byte as int / 16) * 16 + byte as int % 16 == byte as int);
            assert(encoded(bytes).subrange(3, encoded(bytes).len() as int) =~= encoded(rest));
        }
        assert(seq![byte] + rest =~= bytes);
    }
}

/// For the same namespace, equality of actual modelled keys implies equal source paths.
pub proof fn key_injective(prefix: Seq<u8>, left: Seq<u8>, right: Seq<u8>)
    requires key(prefix, left) == key(prefix, right),
    ensures left == right,
{
    let a = key(prefix, left);
    let b = key(prefix, right);
    assert(a.len() == prefix.len() + 4 + encoded(left).len() + 3);
    assert(b.len() == prefix.len() + 4 + encoded(right).len() + 3);
    let begin = prefix.len() as int + 4;
    let end = a.len() as int - 3;
    assert(a.subrange(begin, end) =~= encoded(left));
    assert(b.subrange(begin, end) =~= encoded(right));
    assert(encoded(left) =~= encoded(right));
    round_trip(left);
    round_trip(right);
}
}
