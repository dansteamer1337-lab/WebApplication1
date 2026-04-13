using System.Security.Cryptography;
using System.Text;

namespace WebApplication1.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText, string key, string? iv = null);
        string Decrypt(string cipherText, string key, string? iv = null);
        string GenerateKey(string algorithm);
        string GenerateIV();
    }

    public class EncryptionService : IEncryptionService
    {
        public string Encrypt(string plainText, string key, string? iv = null)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            if (key.Contains("RSA"))
                return EncryptRSA(plainText, key);
            else
                return EncryptAES(plainText, key, iv);
        }

        public string Decrypt(string cipherText, string key, string? iv = null)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            if (key.Contains("RSA"))
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

            var encryptor = aes.CreateEncryptor();
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

            var decryptor = aes.CreateDecryptor();
            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }

        private string EncryptRSA(string plainText, string publicKeyXml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(publicKeyXml);

            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);

            return Convert.ToBase64String(cipherBytes);
        }

        private string DecryptRSA(string cipherText, string privateKeyXml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(privateKeyXml);

            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);

            return Encoding.UTF8.GetString(plainBytes);
        }

        public string GenerateKey(string algorithm)
        {
            if (algorithm == "RSA")
            {
                using var rsa = RSA.Create(2048);
                var publicKey = rsa.ToXmlString(false);
                var privateKey = rsa.ToXmlString(true);
                return $"{publicKey}|{privateKey}";
            }
            else
            {
                using var aes = Aes.Create();
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
    public static class RSAExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            var parameters = new RSAParameters();

            var xmlDoc = new System.Xml.XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.SelectSingleNode("Modulus") is System.Xml.XmlNode modulusNode)
                parameters.Modulus = Convert.FromBase64String(modulusNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("Exponent") is System.Xml.XmlNode exponentNode)
                parameters.Exponent = Convert.FromBase64String(exponentNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("P") is System.Xml.XmlNode pNode)
                parameters.P = Convert.FromBase64String(pNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("Q") is System.Xml.XmlNode qNode)
                parameters.Q = Convert.FromBase64String(qNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("DP") is System.Xml.XmlNode dpNode)
                parameters.DP = Convert.FromBase64String(dpNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("DQ") is System.Xml.XmlNode dqNode)
                parameters.DQ = Convert.FromBase64String(dqNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("InverseQ") is System.Xml.XmlNode iqNode)
                parameters.InverseQ = Convert.FromBase64String(iqNode.InnerText);

            if (xmlDoc.DocumentElement.SelectSingleNode("D") is System.Xml.XmlNode dNode)
                parameters.D = Convert.FromBase64String(dNode.InnerText);

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters);

            var xmlDoc = new System.Xml.XmlDocument();
            var root = xmlDoc.CreateElement("RSAKeyValue");
            xmlDoc.AppendChild(root);

            root.AppendChild(CreateNode(xmlDoc, "Modulus", parameters.Modulus));
            root.AppendChild(CreateNode(xmlDoc, "Exponent", parameters.Exponent));

            if (includePrivateParameters)
            {
                root.AppendChild(CreateNode(xmlDoc, "P", parameters.P));
                root.AppendChild(CreateNode(xmlDoc, "Q", parameters.Q));
                root.AppendChild(CreateNode(xmlDoc, "DP", parameters.DP));
                root.AppendChild(CreateNode(xmlDoc, "DQ", parameters.DQ));
                root.AppendChild(CreateNode(xmlDoc, "InverseQ", parameters.InverseQ));
                root.AppendChild(CreateNode(xmlDoc, "D", parameters.D));
            }

            return xmlDoc.OuterXml;
        }

        private static System.Xml.XmlNode CreateNode(System.Xml.XmlDocument doc, string name, byte[] value)
        {
            var node = doc.CreateElement(name);
            node.InnerText = Convert.ToBase64String(value);
            return node;
        }
    }
}