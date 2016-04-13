using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Numerics;

namespace WAGER
{
    static class BigIntegerExtension
    {
        public static byte[] ToFixedByteArray(this BigInteger b)
        {
            var bytes = b.ToByteArray();

            if (b.Sign == 1 && (bytes.Length > 1 && bytes[bytes.Length - 1] == 0))
                Array.Resize(ref bytes, bytes.Length - 1);
            return bytes;
        }
    }

    static class ArrayExtensions
    {
        public static byte[] Pad(this byte[] b, int amt)
        {
            Array.Resize(ref b, amt);
            return b;
        }

        public static string ToHexString(this byte[] b)
        {
            return BitConverter.ToString(b);
        }
    }
    // oh fucking boy here we go
    class SRP6
    {
        /*public const int G = 1;
        public const int K = 32;
        public SHA1Managed Hash = new SHA1Managed();
        public BigInteger Generator = new BigInteger(7);*/
        public string Identifier;
        
        /// <summary>
        /// N
        /// </summary>
        public BigInteger Modulus { get { return BigInteger.Parse("0894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", System.Globalization.NumberStyles.HexNumber); } }

        /// <summary>
        /// g
        /// </summary>
        public BigInteger Generator { get { return 7; } }

        /// <summary>
        /// k
        /// </summary>
        public BigInteger Multiplier { get { return 3; } }


        /// <summary>
        /// s - the small S because why the fuck not sjeeesh
        /// </summary>
        public BigInteger Salt;

        /// <summary>
        /// v
        /// </summary>
        public BigInteger Verifier;

        /// <summary>
        /// Client ephemeral value
        /// </summary>
        public BigInteger A;

        /// <summary>
        /// Calculated stuff, client->server
        /// </summary>
        public BigInteger M1; // 20 bits

        public BigInteger M2
        {
            get
            {
                return Hash(A.ToFixedByteArray(), M1.ToFixedByteArray(), SessionKey.ToFixedByteArray());
            }
        }


        /// <summary>
        /// b 
        /// </summary>
        public BigInteger PrivateB;

        /// <summary>
        /// Server ephemeral
        /// </summary>
        public BigInteger B
        {
            get
            {
                return (Multiplier * Verifier + BigInteger.ModPow(Generator, PrivateB, Modulus)) % Modulus;
            }
        }

        public BigInteger SessionKey
        {
            get
            {
                return Interleave(BigInteger.ModPow(A * BigInteger.ModPow(Verifier, Hash(A.ToFixedByteArray(), B.ToFixedByteArray()), Modulus), PrivateB, Modulus));
            }
        }

        public BigInteger GenerateM1()
        {
            var N = Hash(Modulus.ToFixedByteArray()).ToByteArray();
            var g = Hash(Generator.ToFixedByteArray()).ToByteArray();

            for (int i = 0, j = N.Length; i < j; i++)
                N[i] ^= g[i];

            return Hash(N, Hash(Encoding.ASCII.GetBytes(Identifier)).ToFixedByteArray(), Salt.ToFixedByteArray(), A.ToFixedByteArray(), B.ToFixedByteArray(), SessionKey.ToFixedByteArray());

            //   return Hash(N, Hash(Encoding.ASCII.GetBytes(Identifier)).ToFixedByteArray(), Salt.ToFixedByteArray(), A.ToFixedByteArray(), B.ToFixedByteArray(), SessionKey.ToFixedByteArray());
        }

        private static BigInteger Interleave(BigInteger sessionKey)
        {
            var T = sessionKey.ToFixedByteArray().SkipWhile(b => b == 0).ToArray(); // Remove all leading 0-bytes
            if ((T.Length & 0x1) == 0x1) T = T.Skip(1).ToArray(); // Needs to be an even length, skip 1 byte if not
            var G = Hash(Enumerable.Range(0, T.Length).Where(i => (i & 0x1) == 0x0).Select(i => T[i]).ToArray()).ToFixedByteArray();
            var H = Hash(Enumerable.Range(0, T.Length).Where(i => (i & 0x1) == 0x1).Select(i => T[i]).ToArray()).ToFixedByteArray();

            var result = new byte[40];
            for (int i = 0, r_c = 0; i < result.Length / 2; i++)
            {
                result[r_c++] = G[i];
                result[r_c++] = H[i];
            }


            return new BigInteger(result/*.Concat(new byte[] { 0x0 }).ToArray()*/);
        }

        public SRP6(string identifier, string password)
        {
            Identifier = identifier;
            Salt = GenerateRandom(32) % Modulus;
            Verifier = GetVerifier(identifier, password, Modulus, Generator, Salt);
        }

        public static BigInteger GetVerifier(string identifier, string password, BigInteger mod, BigInteger gen, BigInteger salt)
        {
            var pk = Hash(salt.ToFixedByteArray(), Hash(Encoding.ASCII.GetBytes(identifier + ":" + password)).ToFixedByteArray());
            return BigInteger.ModPow(gen, pk, mod);
        }

        public static BigInteger GenerateRandom(uint length)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();

            var data = new byte[length];
            provider.GetNonZeroBytes(data);

            return new BigInteger(data.Concat(new byte[] { 0x0 }).ToArray());
        }

        public static BigInteger Hash(params byte[][] args)
        {
            var sha = SHA1.Create();
            return new BigInteger(sha.ComputeHash(args.SelectMany(x => x).ToArray()).Concat(new byte[] { 0x0 }).ToArray());
        }

        public bool Authenticate
        {
            get
            {
                return M1 == M2;
            }
        }
    }
}
