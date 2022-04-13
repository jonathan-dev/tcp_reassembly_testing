## Description
The python files contained in this directory are meant to be placed on
host which TCP implementation is supposed to be tested.
The program simply opens a normal TCP socket and sends back the received
bytes once a fin packet is received.

## Requirements

In order to run the python files a Python 3 installation is required.

## Execution
In order to wait for TCP streams initiated by the test framework subcommand
test-os or the tcp replay run:

```python all_requests.py```
