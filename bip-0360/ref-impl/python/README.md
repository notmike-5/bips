
# p2tsh Python Implementation and Test Vectors

This project contains a simple implementation of functions used to form and spend both Pay-to-Taproot (p2tr) and Pay-to-Tapscript-Hash (p2tsh) transaction outputs. Its purpose is to demonstrate the differences and the commonalities between the extant p2tr transaction output type and that of the proposed p2tsh.

# How to Use

# Dependencies

This project was developed with `Python 3.13.x`, but any modern interpreter should do just nice.

# Clone the Repository

``` bash
git clone https://github.com/notmike-5/bips.git
```
(Optional: You could clone with `--recurse-submodules` here, but this will also load submodules from any BIP that has them.)

# Initialize Submodules

If you did not clone with `git clone --recurse-submodules` then you will need to initialize the bitcointools submodule in the BIP-0360 repository.

To do this, run...
``` bash
cd bips/bip-0360/ref-impl/python

git submodule init && git submodule update
```


# (Optional) Create a Python Virtual Environment and Activate it

It is good practice to explore these things in a local virtual environment. Here is a minimal example:

``` bash
python -m venv .venv
source .venv/bin/activate
```
You may deactivate the virtualenv anytime later by calling `deactivate`.

# Get Python Dependencies

Python dependencies can be installed with  `python -m pip -r requirements.txt`.

# Tests (finally)

To run unit tests,

``` bash
source test.sh
```

# Examples

Other instructive and end-to-end examples can be found in `examples/`
