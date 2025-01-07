# VAZ256™

Verified Abbreviated Zeta 256 bits (VAZ256) - is a post-quantum cryptographic digital signature scheme that combines Dilithium5 and SHAKE256 for secure digital signatures and efficient compressed 32-byte public keys.

## Acknowledgments and Third-Party Code

This project includes modified code from the following open-source projects:

- Parts of CRYSTALS-Dilithium Rust implementation by Quantum Blockchains
  - Original Repository: https://github.com/Quantum-Blockchains/dilithium
  - Files: [list of specific files containing modified code]
  - Original License: GPL-3.0
  - Which itself was ported from the reference implementation at: https://github.com/pq-crystals/dilithium

VAZ256™ is built upon these foundations but includes significant modifications and original work. The name "VAZ256" is a trademark of Fran Luis Vazquez Alonso.

## Features
- Hybrid post-quantum security based on Dilithium5
- Compact 32-byte public keys using SHAKE256
- Pure Rust implementation
- Zero-dependency core functionality
- Comprehensive test suite and benchmarks

## Security Considerations - **Use at Your Own Risk**
- This implementation is currently in development and has not been audited
- Use in production systems is not recommended until formal security analysis is complete

## Performance
Benchmark results and performance characteristics using RockChip RK3562 2.0 GHz.
- Key generation time ~ 1.33 ms
- Signing time ~ 5.00 ms
- Signature verification time ~ 1.01 ms

## Documentation
Full documentation is available at [docs.rs/vaz256](https://docs.rs/vaz256)

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Copyright and License

Copyright (C) 2025 Fran Luis Vazquez Alonso

VAZ256™ is a trademark of Fran Luis Vazquez Alonso. The name "VAZ256" and "Verified Abbreviated Zeta" may not be used for derivative works without express permission.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

### Contact Information
- Email: cybervazquez@protonmail.com

The complete text of the GNU General Public License can be found in the LICENSE file
in this repository or at <https://www.gnu.org/licenses/>.