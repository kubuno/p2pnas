//! Tiny P2P client for manual testing against a running node.
//!   cargo run -p p2pnas-p2p --example p2pcli -- <addr> ping
//!   cargo run -p p2pnas-p2p --example p2pcli -- <addr> store <fragment_id> <text>
//!   cargo run -p p2pnas-p2p --example p2pcli -- <addr> get <fragment_id>
use p2pnas_p2p::{request, P2pMessage};

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: p2pcli <addr> ping | store <frag> <text> | get <frag>");
        std::process::exit(2);
    }
    let (addr, cmd) = (&a[1], a[2].as_str());
    let msg = match cmd {
        "ping" => P2pMessage::Ping { peer_id: "cli".into(), api_port: 0 },
        "store" => P2pMessage::StoreShard {
            fragment_id: a[3].clone(),
            owner_peer_id: "cli".into(),
            data: a[4].clone().into_bytes(),
        },
        "get" => P2pMessage::GetShard { fragment_id: a[3].clone() },
        _ => { eprintln!("unknown command {cmd}"); std::process::exit(2); }
    };
    match request(addr, &msg).await {
        Ok(r) => println!("{r:?}"),
        Err(e) => { eprintln!("error: {e}"); std::process::exit(1); }
    }
}
