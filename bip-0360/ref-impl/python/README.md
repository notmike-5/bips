
# p2tsh Python Implementation and Test Vectors

This project contains a simple implementation of functions used to form and spend both Pay-to-Taproot (p2tr) and Pay-to-Tapscript-Hash (p2tsh) transaction outputs. Its purpose is to demonstrate the differences and the commonalities between the extant p2tr transaction output type and that of the proposed p2tsh.

# How to Use

# (Optional) Create a Python Virtual Environment and Activate it

It is good practice to explore these things in a local virtual environment. Here is a minimal example:

``` bash
python -m venv .venv
source .venv/bin/activate
```
You may deactivate later by calling `deactivate`.

# Install Dependencies

This project was developed with `Python 3.13.x`, but any modern interpreter should do just nice.

Python dependencies can be installed with  `python -m pip -r requirements.txt`

# Clone the Repository

``` bash
git clone https://github.com/notmike-5/bips.git
```
(Optional: You could clone with `--recurse-submodules` here, but this will also load submodules from any BIP that has them.)

# Initialize Submodules

If you did not clone with `git clone --recurse-submodules` then you will need to initialize the bitcointools submodule.

To do this, run `git submodule init && git submodule update` from inside the already cloned repository.

# Tests

To run unit tests,

``` bash
source test.sh
```

# Examples

Other instructive and end-to-end examples can be found in `examples/`
