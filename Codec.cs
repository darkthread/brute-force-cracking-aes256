using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class CodecNetFx
{
    private class AesKeyIV
    {
        public Byte[] Key = new Byte[32];
        public Byte[] IV = new Byte[16];
        public AesKeyIV(string strKey)
        {
            var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(strKey));
            Array.Copy(hash, 0, Key, 0, 32);
            new Random().NextBytes(IV);
        }
    }
    public static (byte[] data, byte[] iv) AesEncrypt(string key, byte[] data)
    {
        var keyIv = new AesKeyIV(key);
        var aes = Aes.Create();
        aes.Key = keyIv.Key;
        aes.IV = keyIv.IV;
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms,
                aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                return (ms.ToArray(), keyIv.IV);
            }
        }
    }

    public static byte[] AesDecrypt(string key, byte[] data, byte[] iv)
    {
        var keyIv = new AesKeyIV(key);
        var aes = Aes.Create();
        aes.Key = keyIv.Key;
        aes.IV = iv;
        using (var ms = new MemoryStream(data))
        {
            using (var cs = new CryptoStream(ms,
                aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                using (var sr = new StreamReader(cs))
                {
                    using (var dec = new MemoryStream())
                    {
                        cs.CopyTo(dec);
                        return dec.ToArray();
                    }
                }
            }
        }
    }
}