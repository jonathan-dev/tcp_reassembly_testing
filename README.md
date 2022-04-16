# Description


## Installation
The whole project was developed on arch Linux

To simplify the installation of the project a `Dockerfile` is provided.

In order to build the docker image we have to `cd` into the base folder
of the repo (where the `Dockerfile` is located).
Here the following command can be run:
```sudo docker build --tag reassembly_test_framework .```

After that we can launch the Docker image interactively using:
```sudo docker run -i -t --network host reassembly_test_framework
/bin/bash```

The `--network host` part of the command is important for using the
`test-os` subcommand of the test framework.

## Usage
Inside the docker image we can run `cd /home/test_framework`.
Inside this folder we can run `cargo run` to execute the framework. This
will list all the subcommands of the framework with an explanation.
It is important to run the `install` subcommand first.

### Testing libraries

### Testing Operating Systems
