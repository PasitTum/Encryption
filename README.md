# 🔒 .NET Cryptography Utility (TripleDES Implementation)

โปรเจกต์นี้เป็น Utility Class ที่เขียนด้วยภาษา **C# (.NET)** เพื่อทำหน้าที่ในการเข้ารหัส (Encryption) และถอดรหัส (Decryption) ข้อมูลแบบ Symmetric โดยใช้โปรโตคอล **TripleDES** เพื่อโชว์ทักษะการจัดการด้าน Data Security และการเขียนโค้ดระดับ Enterprise

## 🛠 Features

* **Secure Implementation**: ใช้ `ICryptoTransform` ร่วมกับ `TripleDESCryptoServiceProvider` เพื่อการจัดการข้อมูลที่ปลอดภัย
* **Memory Efficiency**: ใช้ `using` statements เพื่อจัดการ Memory Management และคืนทรัพยากร (Dispose) ของ CryptoStreams อย่างถูกต้อง
* **Flexible Key Management**: รองรับทั้งการใช้ Default Service Key และการส่ง Custom Keys/IV ผ่าน Parameters
* **Defensive Programming**: มีระบบ Error Handling ที่ครอบคลุม พร้อม `TryDecrypt` Pattern เพื่อลดโอกาสการเกิด Runtime Exception ในระบบจริง

<!-- ## 🚀 How to Use -->

### 1. Basic Encryption
```csharp
string plainText = "Sensitive Data Here";
string cipherText = EncryptionHelper.Encrypt(plainText);

string encryptedData = "base64-encoded-string";
string myKey = "0yo;kIb=pN12345678901234"; // 24-byte key
string decryptedResult = "";

if (EncryptionHelper.TryDecrypt(encryptedData, myKey, ref decryptedResult)) {
    Console.WriteLine($"Result: {decryptedResult}");
}

Architecture & Design Patterns

Helper Pattern: ออกแบบให้เป็น Static Class เพื่อให้เรียกใช้งานได้ง่ายทั่วทั้งแอปพลิเคชัน (Cross-cutting concern)   


Separation of Concerns: มีการแยกส่วนการดึง Secret Key และ Initialization Vector (IV) ออกเป็น Private Methods เพื่อให้อ่านและบำรุงรักษาโค้ดได้ง่าย
