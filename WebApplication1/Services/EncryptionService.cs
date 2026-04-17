using System.Security.Cryptography;
using System.Text;

namespace WebApplication1.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText, string key, string? iv = null, string? algorithm = null);
        string Decrypt(string cipherText, string key, string? iv = null, string? algorithm = null);
        string GenerateKey(string algorithm);
        string GenerateIV();
    }

    public class EncryptionService : IEncryptionService
    {
        public string Encrypt(string plainText, string key, string? iv = null, string? algorithm = null)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            if (algorithm == "RSA")
                return EncryptRSA(plainText, key);
            else
                return EncryptAES(plainText, key, iv);
        }

        public string Decrypt(string cipherText, string key, string? iv = null, string? algorithm = null)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            if (algorithm == "RSA")
                return DecryptRSA(cipherText, key);
            else
                return DecryptAES(cipherText, key, iv);
        }

        private string EncryptAES(string plainText, string keyBase64, string? ivBase64)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(keyBase64);
            aes.IV = !string.IsNullOrEmpty(ivBase64)
                ? Convert.FromBase64String(ivBase64)
                : aes.IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(cipherBytes);
        }

        private string DecryptAES(string cipherText, string keyBase64, string? ivBase64)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(keyBase64);
            aes.IV = !string.IsNullOrEmpty(ivBase64)
                ? Convert.FromBase64String(ivBase64)
                : aes.IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }

        private string EncryptRSA(string plainText, string fullKey)
        {
            // Извлекаем публичную часть ключа
            string publicKeyStr;
            if (fullKey.Contains("@@"))
                publicKeyStr = fullKey.Split(new[] { "@@" }, StringSplitOptions.None)[0];
            else
                publicKeyStr = fullKey;

            var parts = publicKeyStr.Split('|');
            if (parts.Length != 2)
                throw new ArgumentException($"Неверный формат публичного ключа RSA. Получено: {publicKeyStr}");

            using var rsa = RSA.Create();
            var parameters = new RSAParameters
            {
                Modulus = Convert.FromBase64String(parts[0]),
                Exponent = Convert.FromBase64String(parts[1])
            };
            rsa.ImportParameters(parameters);

            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);

            return Convert.ToBase64String(cipherBytes);
        }

        private string DecryptRSA(string cipherText, string fullKey)
        {
            // Извлекаем приватную часть ключа
            string privateKeyStr;
            if (fullKey.Contains("@@"))
                privateKeyStr = fullKey.Split(new[] { "@@" }, StringSplitOptions.None)[1];
            else
                privateKeyStr = fullKey;

            var parts = privateKeyStr.Split('|');
            if (parts.Length != 8)
                throw new ArgumentException($"Неверный формат приватного ключа RSA. Получено частей: {parts.Length}");

            using var rsa = RSA.Create();
            var parameters = new RSAParameters
            {
                Modulus = Convert.FromBase64String(parts[0]),
                Exponent = Convert.FromBase64String(parts[1]),
                D = Convert.FromBase64String(parts[2]),
                P = Convert.FromBase64String(parts[3]),
                Q = Convert.FromBase64String(parts[4]),
                DP = Convert.FromBase64String(parts[5]),
                DQ = Convert.FromBase64String(parts[6]),
                InverseQ = Convert.FromBase64String(parts[7])
            };
            rsa.ImportParameters(parameters);

            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);

            return Encoding.UTF8.GetString(plainBytes);
        }

        public string GenerateKey(string algorithm)
        {
            if (algorithm == "RSA")
            {
                using var rsa = RSA.Create(2048);
                var parameters = rsa.ExportParameters(true);

                // Публичный ключ: modulus|exponent
                var publicKey = $"{Convert.ToBase64String(parameters.Modulus)}|{Convert.ToBase64String(parameters.Exponent)}";

                // Приватный ключ: modulus|exponent|d|p|q|dp|dq|inverseQ
                var privateKey = $"{Convert.ToBase64String(parameters.Modulus)}|" +
                                $"{Convert.ToBase64String(parameters.Exponent)}|" +
                                $"{Convert.ToBase64String(parameters.D)}|" +
                                $"{Convert.ToBase64String(parameters.P)}|" +
                                $"{Convert.ToBase64String(parameters.Q)}|" +
                                $"{Convert.ToBase64String(parameters.DP)}|" +
                                $"{Convert.ToBase64String(parameters.DQ)}|" +
                                $"{Convert.ToBase64String(parameters.InverseQ)}";

                return $"{publicKey}@@{privateKey}";
            }
            else
            {
                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateKey();
                return Convert.ToBase64String(aes.Key);
            }
        }

        public string GenerateIV()
        {
            using var aes = Aes.Create();
            aes.GenerateIV();
            return Convert.ToBase64String(aes.IV);
        }
    }
}