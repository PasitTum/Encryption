using System.Security.Cryptography;

namespace Encryption
{
    public class EncryptionHelper
    {
        // The initialization vector to use for the symmetric algorithm.
	private static readonly byte[] SERVICE_IV = new byte[]
	{
	    82, 55, 97, 46, 79, 88, 61, 92
	};
	
	private static readonly byte[] SERVICE_KEY = new byte[]
	{
	    0xb1, 72, 45, 36, 84, 57, 0x93, 68,
	    0xaf, 0x4d, 65, 0xf1, 0x2e, 0x4b, 53, 21,
	    48, 0x5f, 23, 0x6d, 31, 0x7e, 61
	};

        private static byte[] GetSecretKey(string keyText)
        {
            //return System.Text.Encoding.ASCII.GetBytes("0yo;kIb=pN12345678901234");
            byte[] secretKeyBytes;
            if (!string.IsNullOrWhiteSpace(keyText))
            {
                secretKeyBytes = System.Text.Encoding.ASCII.GetBytes(keyText);
            }
            else
            {
                secretKeyBytes = SERVICE_KEY;
            }
            return secretKeyBytes;
            //return System.Text.Encoding.ASCII.GetBytes(keyText);
        }

        // The initialization vector must be 8 bytes long. If it is longer than 8 bytes, it is truncated and an exception is not thrown
        private static byte[] GetInitialVector(string iv)
		{
            byte[] secretIVBytes;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                secretIVBytes = System.Text.Encoding.ASCII.GetBytes(iv);
            }
            else
            {
                secretIVBytes = SERVICE_IV;
            }
            return secretIVBytes;
		}


		public static string Encrypt(string data, string secretKey = null, string secretIV = null)
		{
			try
			{
				string encryptedData = string.Empty;


                using (ICryptoTransform transform = new TripleDESCryptoServiceProvider().CreateEncryptor(GetSecretKey(secretKey), GetInitialVector(secretIV)))
				{
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
						{
							byte[] bytes = System.Text.Encoding.UTF8.GetBytes(data);
							cryptoStream.Write(bytes, 0, bytes.Length);
							cryptoStream.FlushFinalBlock();

							encryptedData = Convert.ToBase64String(memoryStream.ToArray());
						}
					}
				}

				return encryptedData;
			}
			catch (Exception ex)
			{
				ex.Source = "EncryptException";
				throw ex;
			}
		}

		public static string Decrypt(string data, string secretKey = null, string secretIV = null)
		{
			try
			{
				string decryptedData = string.Empty;

				using (ICryptoTransform transform = new TripleDESCryptoServiceProvider().CreateDecryptor(GetSecretKey(secretKey), GetInitialVector(secretIV)))
				{
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
						{
							byte[] buffer = Convert.FromBase64String(data);
							cryptoStream.Write(buffer, 0, buffer.Length);
							cryptoStream.FlushFinalBlock();

							decryptedData = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());
						}
					}
				}

				return decryptedData;
			}
			catch (Exception ex)
			{
				ex.Source = "EncryptException";
				throw ex;
			}
		}

		public static bool TryDecrypt(string encryptedData, string secretKey, ref string decryptedData)
		{
			try
			{
				decryptedData = Decrypt(encryptedData, secretKey);
				return true;
			}
			catch (Exception)
			{
				// Logging Data
				return false;
			}
		}
    }
}
