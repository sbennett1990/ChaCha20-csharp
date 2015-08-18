/*
 * Copyright (c) 2015 Scott Bennett
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Text;

namespace ChaCha20Cipher {
    public sealed class ChaCha20Cipher : IDisposable {
        // These are the same constants defined in the reference implementation
        // see http://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
        private static readonly byte[] sigma = Encoding.ASCII.GetBytes("expand 32-byte k");
        private static readonly byte[] tau   = Encoding.ASCII.GetBytes("expand 16-byte k");

        /// <summary>
        /// The ChaCha20 state (aka "context")
        /// </summary>
        private uint[] state;

        /// <summary>
        /// Determines if the objects in this class have been disposed of. Set to 
        /// true by the Dispose() method. 
        /// </summary>
        private bool isDisposed;

        /// <summary>
        /// Set up a new ChaCha20 state. The lengths of the given parameters are 
        /// checked before encryption happens. 
        /// </summary>
        /// <remarks>
        /// See <a href="https://tools.ietf.org/html/rfc7539#page-10">ChaCha20 Spec Section 2.4</a>
        /// for a detailed description of the inputs. 
        /// </remarks>
        /// <param name="key">
        /// A 32-byte (256-bit) key, treated as a concatenation of eight 32-bit 
        /// little-endian integers
        /// </param>
        /// <param name="nonce">
        /// A 12-byte (96-bit) nonce, treated as a concatenation of three 32-bit 
        /// little-endian integers
        /// </param>
        /// <param name="counter">
        /// A 4-byte (32-bit) block counter, treated as a 32-bit little-endian integer
        /// </param>
        public ChaCha20Cipher(byte[] key, byte[] nonce, uint counter) {
            this.state = new uint[16];
            this.isDisposed = false;

            KeySetup(key);
            IvSetup(nonce, counter);
        }

        /// <summary>
        /// Set up the ChaCha state with the given key. A 32-byte key is required 
        /// and enforced. 
        /// </summary>
        /// <param name="key">
        /// A 32-byte (256-bit) key, treated as a concatenation of eight 32-bit 
        /// little-endian integers
        /// </param>
        private void KeySetup(byte[] key) {
            if (key == null) {
                throw new ArgumentNullException("Key is null");
            }
            if (key.Length != 32) {
                throw new ArgumentException(
                    "Key length must be 32. Actual is " + key.Length.ToString()
                );
            }

            state[4] = U8To32Little(key, 0);
            state[5] = U8To32Little(key, 4);
            state[6] = U8To32Little(key, 8);
            state[7] = U8To32Little(key, 12);

            byte[] constants = (key.Length == 32) ? sigma : tau;
            int keyIndex = key.Length - 16;

            state[8]  = U8To32Little(key, keyIndex + 0);
            state[9]  = U8To32Little(key, keyIndex + 4);
            state[10] = U8To32Little(key, keyIndex + 8);
            state[11] = U8To32Little(key, keyIndex + 12);

            state[0] = U8To32Little(constants, 0);
            state[1] = U8To32Little(constants, 4);
            state[2] = U8To32Little(constants, 8);
            state[3] = U8To32Little(constants, 12);
        }

        /// <summary>
        /// Set up the ChaCha state with the given nonce (aka Initialization Vector 
        /// or IV) and block counter. A 12-byte nonce and a 4-byte counter are 
        /// required and enforced. 
        /// </summary>
        /// <param name="nonce">
        /// A 12-byte (96-bit) nonce, treated as a concatenation of three 32-bit 
        /// little-endian integers
        /// </param>
        /// <param name="counter">
        /// A 4-byte (32-bit) block counter, treated as a 32-bit little-endian integer
        /// </param>
        private void IvSetup(byte[] nonce, uint counter) {
            if (nonce == null) {
                // There has already been some state set up. Clear it before exiting. 
                Dispose();
                throw new ArgumentNullException("Nonce is null");
            }
            if (nonce.Length != 12) {
                // There has already been some state set up. Clear it before exiting. 
                Dispose();
                throw new ArgumentException(
                    "Nonce length should be 12. Actual is " + nonce.Length.ToString()
                );
            }

            state[12] = counter;
            state[13] = U8To32Little(nonce, 0);
            state[14] = U8To32Little(nonce, 4);
            state[15] = U8To32Little(nonce, 8);
        }

        /// <summary>
        /// Access the ChaCha state. Read-Only. 
        /// </summary>
        public uint[] State {
            get {
                if (!isDisposed) {
                    return this.state;
                } else {
                    return new uint[16];
                }
            }
        }

        /// <summary>
        /// Encrypt an arbitrary-length plaintext message (input), writing the 
        /// resulting ciphertext to the output buffer. The number of bytes to read 
        /// from the input buffer is determined by numBytes. 
        /// </summary>
        /// <param name="output"></param>
        /// <param name="input"></param>
        /// <param name="numBytes"></param>
        public void EncryptBytes(byte[] output, byte[] input, int numBytes) {
            if (isDisposed) {
                throw new ObjectDisposedException("state", 
                    "The ChaCha state has been cleared (i.e. Dispose() has been called)");
            }
            if (numBytes < 0 || numBytes > input.Length) {
                throw new ArgumentOutOfRangeException("numBytes",
                    "The number of bytes to read must be between [0..input.Length]");
            }

            uint[] x = new uint[16];    // Working buffer
            byte[] tmp = new byte[64];  // Temporary buffer
            int outputOffset = 0;
            int inputOffset = 0;

            while (numBytes > 0) {
                for (int i = 16; i-- > 0; ) {
                    x[i] = this.state[i];
                }

                for (int i = 20; i > 0; i -= 2) {
                    QuarterRound(x, 0, 4,  8, 12);
                    QuarterRound(x, 1, 5,  9, 13);
                    QuarterRound(x, 2, 6, 10, 14);
                    QuarterRound(x, 3, 7, 11, 15);

                    QuarterRound(x, 0, 5, 10, 15);
                    QuarterRound(x, 1, 6, 11, 12);
                    QuarterRound(x, 2, 7,  8, 13);
                    QuarterRound(x, 3, 4,  9, 14);
                }

                for (int i = 16; i-- > 0; ) {
                    ToBytes(tmp, Add(x[i], this.state[i]), 4 * i);
                }

                this.state[12] = AddOne(state[12]);
                if (this.state[12] <= 0) {
                    /* Stopping at 2^70 bytes per nonce is the user's responsibility */
                    this.state[13] = AddOne(state[13]);
                }

                if (numBytes <= 64) {
                    for (int i = numBytes; i-- > 0; ) {
                        output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
                    }

                    return;
                }
                for (int i = 64; i-- > 0; ) {
                    output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
                }

                numBytes -= 64;
                outputOffset += 64;
                inputOffset += 64;
            }
        }

        /// <summary>
        /// n-bit left rotation operation (towards the high bits) for 32-bit 
        /// integers. 
        /// </summary>
        /// <param name="v"></param>
        /// <param name="c"></param>
        /// <returns>The result of (v LEFTSHIFT c)</returns>
        public static uint Rotate(uint v, int c) {
            unchecked {
                return (v << c) | (v >> (32 - c));
            }
        }

        /// <summary>
        /// Unchecked integer exclusive or (XOR) operation. 
        /// </summary>
        /// <param name="v"></param>
        /// <param name="w"></param>
        /// <returns>The result of (v XOR w)</returns>
        public static uint XOr(uint v, uint w) {
            return unchecked(v ^ w);
        }

        /// <summary>
        /// Unchecked integer addition. The ChaCha spec defines certain operations 
        /// to use 32-bit unsigned integer addition modulo 2^32. 
        /// </summary>
        /// <remarks>
        /// <remarks>
        /// See <a href="https://tools.ietf.org/html/rfc7539#page-4">ChaCha20 Spec Section 2.1</a>.
        /// </remarks>
        /// </remarks>
        /// <param name="v"></param>
        /// <param name="w"></param>
        /// <returns>The result of (v + w) modulo 2^32</returns>
        public static uint Add(uint v, uint w) {
            return unchecked(v + w);
        }

        /// <summary>
        /// Add 1 to the input parameter using unchecked integer addition. The 
        /// ChaCha spec defines certain operations to use 32-bit unsigned integer 
        /// addition modulo 2^32. 
        /// </summary>
        /// <remarks>
        /// See <a href="https://tools.ietf.org/html/rfc7539#page-4">ChaCha20 Spec Section 2.1</a>.
        /// </remarks>
        /// <param name="v"></param>
        /// <returns>The result of (v + 1) modulo 2^32</returns>
        public static uint AddOne(uint v) {
            return unchecked(v + 1);
        }

        /// <summary>
        /// The ChaCha Quarter Round operation. It operates on four 32-bit unsigned 
        /// integers within the given buffer at indices a, b, c, and d. 
        /// </summary>
        /// <remarks>
        /// The ChaCha state does not have four integer numbers: it has 16.  So 
        /// the quarter-round operation works on only four of them -- hence the 
        /// name.  Each quarter round operates on four predetermined numbers in 
        /// the ChaCha state. 
        /// See <a href="https://tools.ietf.org/html/rfc7539#page-4">ChaCha20 Spec Sections 2.1 - 2.2</a>.
        /// </remarks>
        /// <param name="x">A ChaCha state (vector). Must contain 16 elements.</param>
        /// <param name="a">Index of the first number</param>
        /// <param name="b">Index of the second number</param>
        /// <param name="c">Index of the third number</param>
        /// <param name="d">Index of the fourth number</param>
        public static void QuarterRound(uint[] x, uint a, uint b, uint c, uint d) {
            if (x == null) {
                throw new ArgumentNullException("X buffer is null");
            }
            if (x.Length != 16) {
                throw new ArgumentException();
            }

            x[a] = Add(x[a], x[b]); x[d] = Rotate(XOr(x[d], x[a]), 16);
            x[c] = Add(x[c], x[d]); x[b] = Rotate(XOr(x[b], x[c]), 12);
            x[a] = Add(x[a], x[b]); x[d] = Rotate(XOr(x[d], x[a]),  8);
            x[c] = Add(x[c], x[d]); x[b] = Rotate(XOr(x[b], x[c]),  7);
        }

        /// <summary>
        /// Currently not used.
        /// </summary>
        /// <param name="output"></param>
        /// <param name="input"></param>
        public static void ChaCha20BlockFunction(byte[] output, uint[] input) {
            if (input == null || output == null) {
                throw new ArgumentNullException();
            }
            if (input.Length != 16 || output.Length != 64) {
                throw new ArgumentException();
            }

            uint[] x = new uint[16];  // Working buffer

            for (int i = 16; i-- > 0; ) {
                x[i] = input[i];
            }

            for (int i = 20; i > 0; i -= 2) {
                QuarterRound(x, 0, 4, 8, 12);
                QuarterRound(x, 1, 5, 9, 13);
                QuarterRound(x, 2, 6, 10, 14);
                QuarterRound(x, 3, 7, 11, 15);

                QuarterRound(x, 0, 5, 10, 15);
                QuarterRound(x, 1, 6, 11, 12);
                QuarterRound(x, 2, 7, 8, 13);
                QuarterRound(x, 3, 4, 9, 14);
            }

            for (int i = 16; i-- > 0; ) {
                ToBytes(output, Add(x[i], input[i]), 4 * i);
            }
        }

        /// <summary>
        /// Convert four bytes of the input buffer into an unsigned 
        /// 32-bit integer, beginning at the inputOffset. 
        /// </summary>
        /// <param name="p"></param>
        /// <param name="inputOffset"></param>
        /// <returns>An unsigned 32-bit integer</returns>
        public static uint U8To32Little(byte[] p, int inputOffset) {
            unchecked {
                return ((uint) p[inputOffset] |
                       ((uint) p[inputOffset + 1] << 8) |
                       ((uint) p[inputOffset + 2] << 16) |
                       ((uint) p[inputOffset + 3] << 24));
            }
        }

        /// <summary>
        /// Serialize the input integer into the output buffer. The input integer 
        /// will be split into 4 bytes and put into four sequential places in the 
        /// output buffer, starting at the outputOffset. 
        /// </summary>
        /// <param name="output"></param>
        /// <param name="input"></param>
        /// <param name="outputOffset"></param>
        public static void ToBytes(byte[] output, uint input, int outputOffset) {
            if (outputOffset < 0) {
                throw new ArgumentOutOfRangeException("outputOffset", 
                    "The buffer offset cannot be negative");
            }

            unchecked {
                output[outputOffset]     = (byte) input;
                output[outputOffset + 1] = (byte) (input >> 8);
                output[outputOffset + 2] = (byte) (input >> 16);
                output[outputOffset + 3] = (byte) (input >> 24);
            }
        }

        #region Destructor and Disposer

        /// <summary>
        /// Clear and dispose of the internal state. The finalizer is only called 
        /// if Dispose() was never called on this cipher. 
        /// </summary>
        ~ChaCha20Cipher() {
            Dispose(false);
        }

        /// <summary>
        /// Clear and dispose of the internal state. Also request the GC not to 
        /// call the finalizer, because all cleanup has been taken care of. 
        /// </summary>
        public void Dispose() {
            Dispose(true);
            /* 
             * The Garbage Collector does not need to invoke the finalizer because 
             * Dispose(bool) has already done all the cleanup needed. 
             */
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// This method should only be invoked from Dispose() or the finalizer. 
        /// This handles the actual cleanup of the resources. 
        /// </summary>
        /// <param name="disposing">
        /// Should be true if called by Dispose(); false if called by the finalizer
        /// </param>
        private void Dispose(bool disposing) {
            if (!isDisposed) {
                if (disposing) {
                    /* Cleanup managed objects by calling their Dispose() methods */
                    
                }

                /* Cleanup any unmanaged objects here */

                if (state != null) {
                    Array.Clear(state, 0, state.Length);
                }

                state = null;
            }

            isDisposed = true;
        }

        #endregion
    }
}
