using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    class AESEncryption
    {
        //36 64 9A F2 6D DE 0C 3A 0F 1E 2D 3C 4B 5A 69 78
        private static byte[] _key1 = { 0x36, 0x64, 0x9A, 0xF2, 0x6D, 0xDE, 0x0C, 0x3A, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78 };

        public static byte[] AESEncrypt(byte[] inputByteArray)
        {
            SymmetricAlgorithm des = Rijndael.Create();
            des.Key = _key1;
            des.IV = _key1;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            byte[] cipherBytes = ms.ToArray();
            cs.Close();
            ms.Close();
            return cipherBytes;
        }

        public static byte[] AESDecrypt(byte[] cipherText)
        {
            SymmetricAlgorithm des = Rijndael.Create();
            des.Key = _key1;
            des.IV = _key1;
            byte[] decryptBytes = new byte[cipherText.Length];
            MemoryStream ms = new MemoryStream(cipherText);
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read);
            cs.Read(decryptBytes, 0, decryptBytes.Length);
            cs.Close();
            ms.Close();
            return decryptBytes;
        }
    }
    class Program
    {
        // 
        //
        static void pause()
        {
            Console.Write("Press any key to continue . . . ");
            Console.ReadKey(true);
        }
        public static string ToHexString(byte[] bytes, String flag = ",") // 0xae00cf => "AE00CF "
        {

            string hexString = string.Empty;

            if (bytes != null)
            {

                StringBuilder strB = new StringBuilder();



                for (int i = 0; i < bytes.Length; i++)
                {

                    strB.Append(bytes[i].ToString("X2"));
                    strB.Append(flag);
                }

                hexString = strB.ToString();

            }

            return hexString;

        }
        static void Main(string[] args)
        {
            /*
            byte[] inputByteArray = { 0xAA, 0x55, 0xBB, 0x66, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] outputByteArray = AESEncryption.AESEncrypt(inputByteArray);
            byte[] outputByteArray1 = AESEncryption.AESDecrypt(outputByteArray);
            */

            //*
            Aes.KeySize keysize;
            keysize = Aes.KeySize.Bits128;
            //byte[] inputByteArray = { 0xAA, 0x55, 0xBB, 0x66, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] inputByteArray = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 112, 13, 12, 15, 14 };
            Console.WriteLine("Write key for encryption: ");
            var _key = string.Empty;
            hideKey(_key);
            byte[] _keyB = Encoding.ASCII.GetBytes(_key);
            Aes a = new Aes(keysize, _keyB);
            byte[] outputByteArray = new byte[16];
            a.Cipher(inputByteArray, outputByteArray);
            byte[] outputByteArray1 = new byte[16];
            a.InvCipher(outputByteArray, outputByteArray1);

            string hex2 = ToHexString(outputByteArray);
            string hex1 = ToHexString(outputByteArray1);
            Console.WriteLine("Input - " + hex1);
            Console.WriteLine("Output - " + hex2);
            a.Dump();
            pause();
        }

        public static void hideKey(String privateKey)
        {
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && privateKey.Length > 0)
                {
                    Console.Write("\b \b");
                    privateKey = privateKey[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    privateKey += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
        }
    }
}
