## Todo

- ~~Pessimistic status line parsing~~
- ~~Status Code handling~~
- ~~Redirect handling~~
- ~~Bounded retries for connect/read failures~~
- ~~partial send/recv handling~~
- ~~Strict response validation: status classes, malformed headers, truncated bodies, and timeout cases~~
- ~~non identity encoding handling~~
- ~~transport abstraction~~
- ~~bearssl integration~~

- pure nonblocking socket
    - ~~read w timeout: upgrade to read then poll model~~
    - make connect non-blocking w timeout
    - write w timeout: make request/body writes deadline-aware

- transport correctness tests
    - partial read/write and `EAGAIN` retries preserve one timeout deadline
    - stalled TCP and TLS peers fail on timeout
    - fragmented TLS records drive `run_brssl_engine()` to application data
    - distinguish TLS `close_notify` from an abrupt socket close

- ~~Sink Handling~~
- Proper Error handling - Deterministic failure handling - Proper Cleanup

- Refactoring
    - ~~naming~~
    - ~~fn param pos~~
    - ~~is dispose clean?~~
- ~~remove strncpy~~

- make CA bundle configurable?
- maybe add a max size bound for line buffer?
- restrict to tls1.2?
