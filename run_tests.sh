#!/bin/bash

cd solution;
cargo build;
cargo run &
server_pid=$!
cd ../testing;
sleep 1;
cargo run;
kill $server_pid;