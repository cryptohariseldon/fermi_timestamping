fn main(){let nonce=[42u8;32];println!("{:?}",rt_ping::get_timestamp(nonce).unwrap());}
