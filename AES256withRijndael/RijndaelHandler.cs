using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES256withRijndael
{
    public static class RijndaelHandler
    {
        public static void ExecuteCryptoTest()
        {
            string documentFilePath = "../../00_Documents/test.txt";
            string encryptedFilePath = "../../01_Encrypt/test.txt";
            string decryptedFilePath = "../../02_Decrypt/test.txt";

            try
            {
                // Create a new instance of the RijndaelManaged class.
                using (RijndaelManaged rijndael = new RijndaelManaged())
                {
                    rijndael.KeySize = 256;
                    rijndael.BlockSize = 128;
                    rijndael.Mode = CipherMode.CBC;
                    rijndael.GenerateKey();
                    rijndael.GenerateIV();

                    //Console.WriteLine("Key: " + BitConverter.ToString(rijndael.Key) + "  size [bit]: " + rijndael.Key.Length * 8);
                    //Console.WriteLine("IV: " + BitConverter.ToString(rijndael.IV) + "  size [bit]: " + rijndael.IV.Length * 8);

                    // Encrypt the string to an array of bytes.
                    EncryptFileToEncryptedFile(documentFilePath, encryptedFilePath, rijndael);
                    DecryptEncryptedFileToPlainFile(encryptedFilePath, decryptedFilePath, rijndael);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }
        public static void EncryptFileToEncryptedFile(string filePathPlainFile, string filePathEncryptedFile, RijndaelManaged rijndael)
        {
            // Check input arguments
            if (filePathPlainFile == null || filePathPlainFile.Length <= 0)
                throw new ArgumentNullException("Path of plain text file is empty.");
            if (filePathEncryptedFile == null || filePathEncryptedFile.Length <= 0)
                throw new ArgumentNullException("Path of encrypted text file is empty.");
            if (rijndael == null)
                throw new ArgumentNullException("Rijndael-object is not set.");

            // Create an encryptor with key and initialization vector IV (set in rijndael-object) to perform CBS encryption
            ICryptoTransform encryptor;
            try
            {
                encryptor = rijndael.CreateEncryptor();
            }
            catch (Exception e)
            {
                throw new Exception($"Encryptor cannot be created! Check the key or initialization vector of rijndael. Error: {e.Message}");
            }

            // Change file type of encrypted file
            string modifiedFilePathEncFile = filePathEncryptedFile + ".enc";
            // Create byte data array for cipher blocks (128 bit / 8 = 16 byte)
            byte[] data = new byte[rijndael.BlockSize / 8];

            // inFileStream -> import plain data
            FileStream inFileStream;
            // outFileStream -> export encrypted data
            FileStream outFileStream;
            // cryptoStream -> encrypt plain data
            CryptoStream cryptoStream;

            try
            {
                inFileStream = new FileStream(filePathPlainFile, FileMode.Open);
                outFileStream = new FileStream(modifiedFilePathEncFile, FileMode.Create);
                cryptoStream = new CryptoStream(outFileStream, encryptor, CryptoStreamMode.Write);
            }
            catch (Exception e)
            {
                throw new Exception($"Error when creating FileStream-objects. Error message: {e.Message}");
            }

            try
            {
                using (outFileStream)
                {
                    using (cryptoStream)
                    {
                        using (inFileStream)
                        {
                            // encrypt until end of data is reached
                            int totalByteCount;
                            do
                            {
                                // file data is imported -> 16 byte cypher block
                                totalByteCount = inFileStream.Read(data, 0, data.Length);
                                // imported cypher block is encrypted and exported
                                cryptoStream.Write(data, 0, totalByteCount);
                            } while (totalByteCount > 0);

                            inFileStream.Close();
                        }
                        cryptoStream.FlushFinalBlock();
                        cryptoStream.Close();
                    }
                    outFileStream.Close();
                }
            }
            catch (Exception e)
            {
                throw new Exception($"Error when using FileStream-objects. Encryption failed. Error message: {e.Message}");
            }
        }
        public static void DecryptEncryptedFileToPlainFile(string filePathEncryptedFile, string filePathDecryptedFile, RijndaelManaged rijndael)
        {
            // Check input arguments
            if (filePathEncryptedFile == null || filePathEncryptedFile.Length <= 0)
                throw new ArgumentNullException("Path of encrypted text file is empty.");
            if (filePathDecryptedFile == null || filePathDecryptedFile.Length <= 0)
                throw new ArgumentNullException("Path of decrypted text file is empty.");
            if (rijndael == null)
                throw new ArgumentNullException("Rijndael-object is not set.");

            // Create a decryptor with key and initialization vector IV (set in rijndael-object) to perform CBS decryption
            ICryptoTransform decryptor;
            try
            {
                decryptor = rijndael.CreateDecryptor();
            }
            catch (Exception e)
            {
                throw new Exception($"Decryptor cannot be created! Check the key or initialization vector of rijndael. Error: {e.Message}");
            }

            string modifiedFilePathEncryptedFile = filePathEncryptedFile + ".enc";
            // Create byte data array for cipher blocks (128 bit / 8 = 16 byte)
            byte[] data = new byte[rijndael.BlockSize / 8];

            // inFileStream -> import encrypted data
            FileStream inFileStream;
            // outFileStream -> export decrypted data
            FileStream outFileStream;
            // cryptoStream -> decrypt encrypted data
            CryptoStream cryptoStream;

            try
            {
                inFileStream = new FileStream(modifiedFilePathEncryptedFile, FileMode.Open);
                outFileStream = new FileStream(filePathDecryptedFile, FileMode.Create);
                cryptoStream = new CryptoStream(inFileStream, decryptor, CryptoStreamMode.Read);
            }
            catch (Exception e)
            {
                throw new Exception($"Error when creating FileStream-objects. Error message: {e.Message}");
            }

            try
            {
                using (inFileStream)
                {
                    using (cryptoStream)
                    {
                        using (outFileStream)
                        {
                            // decrypt until end of data is reached
                            int totalByteCount;
                            do
                            {
                                // 16 byte cypher block is imported and decrypted
                                totalByteCount = cryptoStream.Read(data, 0, data.Length);
                                // decrypted cypher block is exported
                                outFileStream.Write(data, 0, totalByteCount);
                            } while (totalByteCount > 0);

                            outFileStream.Close();
                        }
                        cryptoStream.Close();
                    }
                    inFileStream.Close();
                }
            }
            catch (Exception e)
            {
                throw new Exception($"Error when using FileStream-objects. Decryption failed. Error message: {e.Message}");
            }
        }

        public static void ExecuteRijndaelManagedExample(string plainText)
        {
            try
            {
                // Create a new instance of the RijndaelManaged class.
                using (RijndaelManaged rijndael = new RijndaelManaged())
                {
                    rijndael.KeySize = 256;
                    rijndael.BlockSize = 128;
                    rijndael.Mode = CipherMode.CBC;

                    rijndael.GenerateKey();
                    rijndael.GenerateIV();

                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes(plainText, rijndael.Key, rijndael.IV);

                    // Decrypt the bytes to a string.
                    string roundtrip = DecryptStringFromBytes(encrypted, rijndael.Key, rijndael.IV);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", plainText);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }
        public static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;
            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijndael = new RijndaelManaged())
            {
                rijndael.Key = key;
                rijndael.IV = iv;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        public static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
