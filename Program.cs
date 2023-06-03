using System.Diagnostics;
using System.Threading.Channels;

int pwdLength = 3;
string pwdCharSet = "*"; // N-Number, A-AlphaDigit, *-Any
if (args.Length > 0)
    int.TryParse(args[0], out pwdLength);
if (args.Length > 1)
    pwdCharSet = args[1];

// 密碼字元範圍：ASCII 32~126
char[] pwdChars;
switch (pwdCharSet)
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
Console.WriteLine($"隨機密碼: {password}");
Console.WriteLine($"AES加密內容: {BitConverter.ToString(ecn.data.Take(32).ToArray())}...");
Console.WriteLine($"AES-CBC IV: {BitConverter.ToString(ecn.iv)}");

var cts = new CancellationTokenSource();
var token = cts.Token;
var sw = new Stopwatch();
var startTime = DateTime.Now;
long total = Enumerable.Range(1, pwdLength).Sum(i => Convert.ToInt64(Math.Pow(pwdChars.Length, i)));
long queued = 0;
long completed = 0;
Func<bool> done = () => completed >= total;

var channel = Channel.CreateBounded<string>(65536 * 64);
Task.Run(() =>
    {
        // 檢查 CancellationTokenSource 是否已經被取消
        while (!token.IsCancellationRequested)
        {
            Console.CursorLeft = 0;
            Console.Write($"{(DateTime.Now - startTime).TotalSeconds,3:n0}s | {queued:n0} | {completed:n0}/{total:n0} {completed * 1.0 / total:p0}");
            if (done()) cts.Cancel();
            Thread.Sleep(1000);
        }
    },
    token //允許還沒執行前取消(例如：還在 Queue 排隊時就取消)
);
var consumers = Enumerable.Range(1, Environment.ProcessorCount).Select(o => Task.Run(async () =>
{
    try
    {
        while (await channel.Reader.WaitToReadAsync(token))
        {
            var pwd = await channel.Reader.ReadAsync(token);
            if (!token.IsCancellationRequested)
            {
                try
                {
                    var dec = CodecNetFx.AesDecrypt(pwd, ecn.data, ecn.iv);
                    if (dec.SequenceEqual(plain))
                    {
                        Console.WriteLine($"取得密碼：{pwd}");
                    }
                }
                catch { }
                finally
                {
                    Interlocked.Increment(ref completed);
                }
            }
        }
    }
    catch (OperationCanceledException) { 
    }
})).ToArray();


sw.Start();
explore(string.Empty);
// channel.Writer.Complete();
Task.WaitAll(consumers);
Console.WriteLine();
cts.Cancel();
sw.Stop();
Console.WriteLine($"嘗試所有組合耗時: {sw.ElapsedMilliseconds:n0}ms");


// DFS 產生所有組合
async Task explore(string pfx)
{
    var pwd = pfx;
    if (!string.IsNullOrEmpty(pwd))
    {
        queued++;
        if (await channel.Writer.WaitToWriteAsync())
            channel.Writer.TryWrite(pwd);
    }
    if (pfx.Length < pwdLength)
        foreach (var c in pwdChars)
        {
            await explore(pfx + c);
        }
}

