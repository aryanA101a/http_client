# http_client

This is a standalone http/https client waiting to be integrated into freebsd/stand/kboot/

## Clone

```sh
git clone --recurse-submodules https://github.com/aryanA101a/http_client
```

If you already cloned without submodules:

```sh
git submodule update --init
```

## Build

```sh
bmake
```

## Run

```sh
./build/http_client http://example.com/path
```


## Tests

```sh
python3 -m venv tests/venv
./tests/venv/bin/python -m pip install pytest
./tests/venv/bin/python -m pytest tests -v
```

## Debugging Tests

Run a single pytest case under LLDB by setting `HTTP_CLIENT_LLDB=1`.
Use `HTTP_CLIENT_LLDB_BREAK` to choose the initial breakpoint:

```sh
HTTP_CLIENT_LLDB=1 HTTP_CLIENT_LLDB_BREAK=read_body ./tests/venv/bin/python -m pytest -s tests/test_http_client.py::test_chunked_response_ignores_trailers
```
