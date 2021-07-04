using System;

namespace AES256withRijndael
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("ENCRYPTION and DECRYPTION with AES256");
            RijndaelHandler.ExecuteCryptoTest();
            //RijndaelHandler.ExecuteRijndaelManagedExample("Some secret text to encrypt");
            Console.WriteLine("[ FINISHED ]");
        }
    }
}
