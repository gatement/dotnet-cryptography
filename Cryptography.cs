using System;
using System.Security.Cryptography;
using System.IO;
using System.Web;

namespace jQueryMobileMVC.Code
{
	public class Cryptography
	{
		private static byte[] Key64 = { 42, 12, 94, 157, 72, 4, 218, 32 };
		private static byte[] IV64 = { 51, 103, 251, 79, 36, 93, 163, 1 };
		private static byte[] Key256 = { 42, 12, 94, 157, 72, 4, 218, 32, 51, 103, 251, 79, 36, 93, 163, 1, 53, 101, 211, 179, 136, 94, 113, 10 };
		private static byte[] IV64_2 = { 53, 101, 211, 179, 136, 94, 113, 10 };

		public static string EncryptDES(string valueString)
		{
			if(valueString == null)
			{
				throw new ArgumentException("String to be encrypted can not be null.", "valueString");
			}

			using(DESCryptoServiceProvider desprovider = new DESCryptoServiceProvider())
			using(MemoryStream memoryStream = new MemoryStream())
			using(CryptoStream cryptoStream = new CryptoStream(memoryStream, desprovider.CreateEncryptor(Key64, IV64), CryptoStreamMode.Write))
			using(StreamWriter writerStream = new StreamWriter(cryptoStream))
			{
				writerStream.Write(valueString);
				writerStream.Flush();
				cryptoStream.FlushFinalBlock();

				return Convert.ToBase64String(memoryStream.ToArray());
			}
		}

		public static string DecryptDES(string valueString)
		{
			if(valueString == null)
			{
				throw new ArgumentException("String to be decrypted can not be null.", "valueString");
			}

			byte[] buffer = Convert.FromBase64String(valueString);

			using(DESCryptoServiceProvider desprovider = new DESCryptoServiceProvider())
			using(MemoryStream memoryStream = new MemoryStream(buffer))
			using(CryptoStream cryptoStream = new CryptoStream(memoryStream, desprovider.CreateDecryptor(Key64, IV64), CryptoStreamMode.Read))
			using(StreamReader streamReader = new StreamReader(cryptoStream))
			{
				return (streamReader.ReadToEnd());
			}
		}

		public static string EncryptTripleDES(string valueString)
		{
			if(valueString == null)
			{
				throw new ArgumentException("String to be encrypted can not be null.", "valueString");
			}
			using(TripleDESCryptoServiceProvider desprovider = new TripleDESCryptoServiceProvider())
			using(MemoryStream memoryStream = new MemoryStream())
			using(CryptoStream cryptoStream = new CryptoStream(memoryStream, desprovider.CreateEncryptor(Key256, IV64_2), CryptoStreamMode.Write))
			using(StreamWriter writerStream = new StreamWriter(cryptoStream))
			{
				writerStream.Write(valueString);
				writerStream.Flush();
				cryptoStream.FlushFinalBlock();

				return Convert.ToBase64String(memoryStream.ToArray());
			}
		}

		public static string DecryptTripleDES(string valueString)
		{
			if(valueString == null)
			{
				throw new ArgumentException("String to be decrypted can not be null.", "valueString");
			}

			byte[] buffer = Convert.FromBase64String(valueString);

			using(TripleDESCryptoServiceProvider desprovider = new TripleDESCryptoServiceProvider())
			using(MemoryStream memoryStream = new MemoryStream(buffer))
			using(CryptoStream cryptoStream = new CryptoStream(memoryStream, desprovider.CreateDecryptor(Key256, IV64_2), CryptoStreamMode.Read))
			using(StreamReader streamReader = new StreamReader(cryptoStream))
			{
				return (streamReader.ReadToEnd());
			}
		}
	}
}