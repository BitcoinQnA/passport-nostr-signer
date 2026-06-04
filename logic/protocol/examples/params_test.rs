// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use protocol::message::Request;

fn main() {
    for s in [
        r#"{"id":"a","method":"ping"}"#,
        r#"{"id":"a","method":"ping","params":null}"#,
        r#"{"id":"a","method":"ping","params":{}}"#,
    ] {
        match serde_json::from_str::<Request>(s) {
            Ok(v) => println!("OK:   {s:50} -> {:?}", v.method),
            Err(e) => println!("ERR:  {s:50} -> {e}"),
        }
    }
}
