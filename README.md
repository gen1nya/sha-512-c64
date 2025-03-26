# SHA-512 Implementation for Commodore 64 (cc65-Compatible)

This is a **partial implementation** of the SHA-512 hashing algorithm written in portable C. It is designed to run on **Commodore 64** using the [cc65](https://cc65.github.io/cc65/) C compiler, with emulated 64-bit arithmetic. The implementation can also be compiled on modern platforms using `gcc` for easier testing and debugging.

---

## ⚙️ Features

- 64-bit emulation using `uint32_t[2]` (`uint64_emul`)
- Full SHA-512 compression logic:
  - Bitwise operations: AND, OR, XOR, NOT
  - Shifts and rotates: logical shift left/right, rotate right
  - SHA-512 specific functions: `Ch`, `Maj`, `Sigma0`, `Sigma1`, `sigma0`, `sigma1`
- Internal 1024-bit (128-byte) block processing
- PETSCII → ASCII conversion for C64 compatibility
- Test vectors with known SHA-512 outputs for validation

---

## 💠 Build Instructions

### ✅ Compile on Modern Systems (e.g., Linux/macOS/Windows)

You can compile and test the code using `gcc`:

```bash
gcc -std=c99 -o sha512 sha512_c64.c
./sha512
```

### 📢 Compile for Commodore 64 using cc65

Install [cc65](https://cc65.github.io/cc65/), then run:

```bash
cl65 -O -t c64 -o sha512.prg sha512_c64.c
```

**Explanation of command:**

| Flag        | Meaning                                      |
|-------------|----------------------------------------------|
| `-O`        | Enables code size optimization               |
| `-t c64`    | Sets target platform to Commodore 64         |
| `-o sha512.prg` | Output file in `.prg` format             |
| `sha512_c64.c`  | Source file                                  |

---

## 🧪 Tests

The program includes a built-in `test_known_hashes()` function that runs SHA-512 on test vectors and compares the results against expected hashes:

- `""` (empty string)
- `"abc"`
- `"abcdefghbcdefghicdefghij..."`

Each input is first converted from PETSCII to ASCII before hashing, to ensure compatibility with typical Commodore input formats.

Example output:
```
Test 1:
Input (PETSCII): ''
Converted (ASCII): ''
Hash: cf83e1357eefb8bd...
Match
```

---

## ⚠️ Limitations

- **Partial implementation**: The code includes only the core hashing logic and omits file or stream-based interfaces.
- **Input size limitations**: Due to performance constraints and memory usage, this implementation is intended for hashing relatively short messages.
- **Not thread-safe**: The code uses `static` variables for internal buffers to minimize stack usage, which makes it unsuitable for multi-threaded execution.

---

## 📁 Files

- `sha512_c64.c` — Main implementation
- `sha512` — Precompiled binary for macOS arm64 (built with `gcc`)
- `sha512.prg` — Precompiled binary for Commodore 64 (built with `cc65`)

You can run the `.prg` file using a real C64 or an emulator like [C64 Online Emulator](https://c64online.com/c64-online-emulator/).

---

## 📜 License

This code is released into the **public domain** (CC0). You are free to use, modify, and distribute it for any purpose.

---

## 🤍 Bonus

The code contains a PETSCII → ASCII converter to make it easier to hash input from C64 key input or memory.

```c
unsigned char petscii_to_ascii(unsigned char c) {
    if (c >= 0xC1 && c <= 0xDA)
        return c - 0x60;
    if (c >= 0x41 && c <= 0x5A)
        return c + 0x20;
    return c;
}
```

