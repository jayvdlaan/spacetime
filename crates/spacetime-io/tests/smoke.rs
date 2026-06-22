use spacetime_io as sio;
use spacetime_io::testutil::Sink;

#[test]
fn write_all_smoke() {
    let mut s = Sink::<16>::new();
    let msg = b"hello";
    sio::write_all(&mut s, msg).unwrap();
    assert_eq!(&s.buf[..s.len], &msg[..]);
}
