using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class CryptoViewModel
    {
        [Display(Name = "Исходный текст")]
        public string? PlainText { get; set; }

        [Display(Name = "Зашифрованный текст")]
        public string? EncryptedText { get; set; }

        [Display(Name = "Расшифрованный текст")]
        public string? DecryptedText { get; set; }

        [Display(Name = "Алгоритм шифрования")]
        public string Algorithm { get; set; } = "AES";

        [Display(Name = "Ключ шифрования")]
        public string? Key { get; set; }

        [Display(Name = "IV (для AES)")]
        public string? IV { get; set; }
    }
}