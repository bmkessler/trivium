# trivium
[![GoDoc](https://godoc.org/github.com/bmkessler/trivium?status.svg)](https://godoc.org/github.com/bmkessler/trivium)
[![Build Status](https://travis-ci.org/bmkessler/trivium.svg?branch=master)](https://travis-ci.org/bmkessler/trivium)
[![Coverage Status](https://coveralls.io/repos/github/bmkessler/trivium/badge.svg?branch=master)](https://coveralls.io/github/bmkessler/trivium?branch=master)

A simple golang implementation of the lightweight trivium stream cipher.

DISCLAIMER: This package is purely for fun and makes no claim or waranty of security.
Do not use this package to encrypt any sensitive information.

Trivium is a light weight stream cipher developed to be particularly efficient in hardware.

The trivium specification is http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf

This is a straighforward implementation based on the specification using SWAR calculations
to calculate up to 64 bits at a time.
