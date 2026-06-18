# http_client

## Build

```sh
bmake
```

## Run

```sh
./http_client http://example.com/path
```


## Tests

```sh
./tests/venv/bin/python -m pytest tests -v
```

## Debugging Tests

Run a single pytest case under LLDB by setting `HTTP_CLIENT_LLDB=1`.
Use `HTTP_CLIENT_LLDB_BREAK` to choose the initial breakpoint:

```sh
HTTP_CLIENT_LLDB=1 HTTP_CLIENT_LLDB_BREAK=read_body ./tests/venv/bin/python -m pytest -s tests/test_http_client.py::test_chunked_response_ignores_trailers
```
