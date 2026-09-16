# DNS Bypass v3.0 - Stealth Tunnel Deployment Guide

## 📦 Cloudflare Workers Kurulumu

### Adım 1: Cloudflare Hesabı Oluştur
1. https://dash.cloudflare.com/sign-up adresine git
2. Email ile kayıt ol (ÜCRETSIZ!)
3. Email'i doğrula

### Adım 2: Worker Oluştur
1. Dashboard → Workers & Pages
2. "Create application" tıkla
3. "Create Worker" seç
4. İsim ver: `dns-bypass-worker`
5. "Deploy" tıkla

### Adım 3: Kodu Yapıştır
1. Worker açıldıktan sonra "Edit code" tıkla
2. `cloudflare-worker/dns-tunnel.js` dosyasındaki TAMAMINI kopyala
3. Worker editor'e yapıştır (eski kodu sil)
4. "Save and Deploy" tıkla

### Adım 4: URL'i Kopyala
1. Worker URL'ini kopyala, örnek:
   ```
   https://dns-bypass-worker.YOUR_USERNAME.workers.dev
   ```

2. Bu URL'i `StealthDnsClient.cs` dosyasında güncelle:
   ```csharp
   private static readonly List<string> WorkerEndpoints = new List<string>
   {
       "https://dns-bypass-worker.YOUR_USERNAME.workers.dev", // BURAYA YAPISTIR!
   };
   ```

### Adım 5: Test Et
Browser'da test et:
```
https://dns-bypass-worker.YOUR_USERNAME.workers.dev
```

POST request test (PowerShell):
```powershell
$body = @{
    domain = "youtube.com"
    type = "A"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://dns-bypass-worker.YOUR_USERNAME.workers.dev" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"
```

Cevap alırsan: ✅ Worker çalışıyor!

---

## 🔥 Yedek Worker'lar (Opsiyonel)

Daha güçlü bypass için 2-3 worker daha oluştur:
1. `dns-tunnel-2`
2. `api-gateway`
3. `cdn-proxy`

Her birinin URL'ini `StealthDnsClient.cs`'e ekle!

---

## 🎯 Özellikler

✅ **100% HTTPS** - Normal web trafiği gibi görünür
✅ **Cloudflare CDN** - Engellenemez (tüm siteler Cloudflare kullanıyor)
✅ **Ücretsiz** - 100,000 request/gün
✅ **Düşük Latency** - Cloudflare edge network
✅ **DPI Bypass** - Normal API çağrısı gibi
✅ **Mikrotik Bypass** - Layer 7 tespit edemez

---

## 🛡️ Güvenlik

Worker'lar public ama sadece DNS query yapıyor (zararsız).
Kimse senin trafiğini göremez (end-to-end HTTPS).

---

## 📊 Monitoring

Cloudflare Dashboard → Workers → Metrics
- Request sayısı
- Başarı oranı
- Latency
- Hatalar

---

## 🚀 Production'a Hazır!

Worker deploy edildikten sonra:
1. `StealthDnsClient.cs`'de URL'i güncelle
2. Projeyi derle
3. Test et!
