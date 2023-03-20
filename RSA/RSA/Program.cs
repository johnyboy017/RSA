using System;
using System.Numerics;
using System.Security.Cryptography;

namespace RSA
{
    class RSAKeyGenerator
    {
        static void Main(string[] args)
        {
            int bitSize = 4096;
            BigInteger p, q, n, totient, e, d, dp, dq, inverseQ;
            var random = new Random();

            do
            {
                p = BigInteger.ProbablePrime(bitSize, random);
                q = BigInteger.ProbablePrime(bitSize, random);
            } while (BigInteger.GreatestCommonDivisor(p, q) != 1);

            n = p * q;
            totient = (p - 1) * (q - 1);
            e = BigInteger.One << 16 | 1; // 65537 in binary
            d = ModInverse(e, totient);
            dp = d % (p - 1);
            dq = d % (q - 1);
            inverseQ = q.ModInverse(p);

            var rsa = new RSACryptoServiceProvider(bitSize);
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = n.ToByteArray(),
                Exponent = e.ToByteArray(),
                D = d.ToByteArray(),
                P = p.ToByteArray(),
                Q = q.ToByteArray(),
                DP = dp.ToByteArray(),
                DQ = dq.ToByteArray(),
                InverseQ = inverseQ.ToByteArray()
            });

            Console.WriteLine("Chave pública: {0}", Convert.ToBase64String(rsa.ExportRSAPublicKey()));
            Console.WriteLine("Chave privada: {0}", Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
        }

        static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }
    }
}
