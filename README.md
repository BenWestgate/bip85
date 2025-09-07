# BIP85

Reference implementation for [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki), including support for BIP93 (codex32).

Includes a CLI tool to test the functionality. 

## Example usage 
To generate 5 codex32 shares with threshold 3 from a BIP32 master key:

```sh
bip85-cli --index 0 \
  --xprv xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb \
  bip93 --threshold 3 --n 5
```
For usage details:
```
bip85-cli --help
bip85-cli bip93 --help
```
## Installation
Install the CLI tool using `pipx`:
```sh
git clone https://github.com/benwestgate/bip85
cd bip85
pipx install .
```

## Running tests
```sh
pytest
```
Make sure the package is installed (`pip install -e .`) before running tests.
