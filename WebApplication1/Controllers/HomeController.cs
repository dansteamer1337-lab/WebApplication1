using WebApplication1.Services;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;

namespace CryptoApp.Controllers
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
            model.Key = _encryptionService.GenerateKey("AES");
            model.IV = _encryptionService.GenerateIV();
            return View(model);
        }

        [HttpPost]
        public IActionResult Encrypt(CryptoViewModel model)
        {
            if (ModelState.IsValid && !string.IsNullOrEmpty(model.PlainText))
            {
                model.EncryptedText = _encryptionService.Encrypt(
                    model.PlainText,
                    model.Key,
                    model.Algorithm == "AES" ? model.IV : null
                );
            }

            if (model.Algorithm == "AES" && string.IsNullOrEmpty(model.IV))
                model.IV = _encryptionService.GenerateIV();

            return View("Index", model);
        }

        [HttpPost]
        public IActionResult Decrypt(CryptoViewModel model)
        {
            if (ModelState.IsValid && !string.IsNullOrEmpty(model.EncryptedText))
            {
                model.DecryptedText = _encryptionService.Decrypt(
                    model.EncryptedText,
                    model.Key,
                    model.Algorithm == "AES" ? model.IV : null
                );
            }

            return View("Index", model);
        }

        [HttpPost]
        public IActionResult GenerateKey(CryptoViewModel model)
        {
            model.Key = _encryptionService.GenerateKey(model.Algorithm);
            if (model.Algorithm == "AES")
                model.IV = _encryptionService.GenerateIV();

            return View("Index", model);
        }
    }
}