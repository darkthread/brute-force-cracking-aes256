using System.Diagnostics;

int pwdLength = 4;
string pwdCharSet = "n"; // N-Number, A-AlphaDigit, *-Any
if (args.Length > 0)
    int.TryParse(args[0], out pwdLength);
if (args.Length > 1)
    pwdCharSet = args[1];
// 密碼字元範圍：ASCII 32~126
char[] pwdChars;
switch (pwdCharSet.ToUpper())
{
    case "N":
        pwdChars = "0123456789".ToArray();
        break;
    case "A":
        pwdChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToArray();
        break;
    default: // All
        pwdChars = Enumerable.Range(32, 95).Select(i => (char)i).ToArray();
        break;
}

// 原始資料：1KB byte[]
var plain = new byte[1024];
// 隨機密碼：4字元
var password = new string(Enumerable.Range(0, pwdLength).Select(i => pwdChars[new Random().Next(pwdChars.Length)]).ToArray());
var ecn = CodecNetFx.AesEncrypt(password, plain);
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("SAH256 產生 AES256 金鑰暴力破解測試");
Console.ResetColor();
Console.WriteLine($"密碼長度: {pwdLength}");
Console.WriteLine($"可用密碼字元: {new string(pwdChars)}");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine($"隨機密碼: {password}");
Console.ResetColor();
Console.WriteLine($"AES加密內容: {BitConverter.ToString(ecn.data.Take(16).ToArray())}...");
Console.WriteLine($"AES-CBC IV: {BitConverter.ToString(ecn.iv)}");

var cts = new CancellationTokenSource();
var token = cts.Token;
var sw = new Stopwatch();
var startTime = DateTime.Now;
long total = Enumerable.Range(1, pwdLength).Sum(i => Convert.ToInt64(Math.Pow(pwdChars.Length, i)));
long errCount = 0;
long completed = 0;
Task.Run(() =>
    {
        // 檢查 CancellationTokenSource 是否已經被取消
        while (!cts.Token.IsCancellationRequested)
        {
            Console.CursorLeft = 0;
            Console.Write($"{(DateTime.Now - startTime).TotalSeconds,3:n0}s | {completed:n0} / {total:n0} ({completed * 1.0 / total:p0}) | {errCount:n0}");
            Thread.Sleep(1000);
        }
    },
    cts.Token //允許還沒執行前取消(例如：還在 Queue 排隊時就取消)
);
var tasks = new List<Task>();
sw.Start();
Parallel.ForEach<string>(explore(""), new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount * 2 },
(pwd) =>
{
    if (token.IsCancellationRequested)
        return;
    try
    {
        var dec = CodecNetFx.AesDecrypt(pwd, ecn.data, ecn.iv);
        if (dec.SequenceEqual(plain))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($" ** 發現密碼：{pwd} **");
            Console.ResetColor();
        }
    }
    catch { 
        Interlocked.Increment(ref errCount);
    }
    finally
    {
        Interlocked.Increment(ref completed);
    }
});

Console.WriteLine();
cts.Cancel();
sw.Stop();
Console.Write($"已嘗試{completed:n0}種組合，");
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine($"耗時: {sw.ElapsedMilliseconds:n0}ms");
Console.ResetColor();

IEnumerable<string> explore(string currPwd)
{
    if (!string.IsNullOrEmpty(currPwd))
        yield return currPwd;
    if (currPwd.Length < pwdLength)
    {
        foreach (var c in pwdChars)
        {
            foreach (var res in explore(currPwd + c))
                yield return res;
        }
    }
}