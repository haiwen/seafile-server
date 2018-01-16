# Seafile Server Tests

## Run it locally

To run the tests, you need to install pytest first:

```sh
pip install -r ci/requirements.txt
```

Then run the tests with
```sh
./run_tests.sh
```

By default the test script would try to start ccnet-server and seaf-server in `/usr/local/bin`, if you `make install` to another location, say `/opt/local`, run it like this:
```sh
SEAFILE_INSTALL_PREFIX=/opt/local ./run_tests.sh
```
