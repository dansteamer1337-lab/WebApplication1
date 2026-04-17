using WebApplication1.Services;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    public class HomeController : Controller
    {
        private readonly IEncryptionService _encryptionService;

        public HomeController(IEncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        public IActionResult Index()
        {
            var model = new CryptoViewModel();
            model.Algorithm = "AES"; // По умолчанию AES
            model.Key = _encryptionService.GenerateKey("AES");
            model.IV = _encryptionService.GenerateIV();
            return View(model);
        }

        [HttpPost]
        public IActionResult Encrypt(CryptoViewModel model)
        {
            // Проверяем, что ключ существует
            if (string.IsNullOrEmpty(model.Key))
            {
                ViewData["ErrorMessage"] = "Ключ не сгенерирован. Нажмите 'Сгенерировать ключ'.";
                return View("Index", model);
            }

            if (!string.IsNullOrEmpty(model.PlainText))
            {
                try
                {
                    model.EncryptedText = _encryptionService.Encrypt(
                        model.PlainText,
                        model.Key,
                        model.Algorithm == "AES" ? model.IV : null,
                        model.Algorithm
                    );
                }
                catch (Exception ex)
                {
                    ViewData["ErrorMessage"] = $"Ошибка шифрования: {ex.Message}";
                }
            }
            else
            {
                ViewData["ErrorMessage"] = "Введите текст для шифрования";
            }

            if (model.Algorithm == "AES" && string.IsNullOrEmpty(model.IV))
                model.IV = _encryptionService.GenerateIV();

            return View("Index", model);
        }

        [HttpPost]
        public IActionResult Decrypt(CryptoViewModel model)
        {
            if (string.IsNullOrEmpty(model.Key))
            {
                ViewData["ErrorMessage"] = "Ключ не сгенерирован.";
                return View("Index", model);
            }

            if (!string.IsNullOrEmpty(model.EncryptedText))
            {
                try
                {
                    model.DecryptedText = _encryptionService.Decrypt(
                        model.EncryptedText,
                        model.Key,
                        model.Algorithm == "AES" ? model.IV : null,
                        model.Algorithm
                    );
                }
                catch (Exception ex)
                {
                    ViewData["ErrorMessage"] = $"Ошибка дешифрования: {ex.Message}";
                }
            }

            return View("Index", model);
        }

        [HttpPost]
        public IActionResult GenerateKey(CryptoViewModel model)
        {
            // Генерируем ключ для выбранного алгоритма
            model.Key = _encryptionService.GenerateKey(model.Algorithm);

            if (model.Algorithm == "AES")
            {
                model.IV = _encryptionService.GenerateIV();
            }
            else if (model.Algorithm == "RSA")
            {
                // Для RSA очищаем IV
                model.IV = null;
            }

            // Очищаем предыдущие результаты
            model.PlainText = null;
            model.EncryptedText = null;
            model.DecryptedText = null;

            return View("Index", model);
        }
    }
}