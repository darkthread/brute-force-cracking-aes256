using System.Diagnostics;

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
var sw = new Stopwatch();
var startTime = DateTime.Now;
var total = Math.Pow(pwdChars.Length, pwdLength);
var queued = 0;
ThreadPool.SetMinThreads(Environment.ProcessorCount * 4, 16);
Task.Run(() =>
    {

        // 檢查 CancellationTokenSource 是否已經被取消
        while (!cts.Token.IsCancellationRequested)
        {
            Console.CursorLeft = 0;
            Console.Write($"{(DateTime.Now - startTime).TotalSeconds,3:n0}s | {ThreadPool.ThreadCount,7} | {ThreadPool.PendingWorkItemCount,7}");
            Thread.Sleep(1000);
        }
    }, 
    cts.Token //允許還沒執行前取消(例如：還在 Queue 排隊時就取消)
);
var tasks = new List<Task>();
sw.Start();
explore(string.Empty);


Task.WaitAll(tasks.ToArray());
Console.WriteLine();
cts.Cancel();
sw.Stop();
Console.WriteLine($"嘗試所有組合耗時: {sw.ElapsedMilliseconds:n0}ms");


// DFS 產生所有組合
void explore(string pfx)
{
    var pwd = pfx;
    if (!string.IsNullOrEmpty(pwd))
    {
        // 雖然 ThreadPool 待處理 Work Item 沒有上限，但為避免耗用過多資源，加上限制
        while (ThreadPool.PendingWorkItemCount > 65535)
        {
            Thread.Sleep(10);
        }
        queued++;
        tasks.Add(Task.Run(() =>
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
        }));
    }
    if (pfx.Length < pwdLength)
        foreach (var c in pwdChars)
        {
            explore(pfx + c);
        }
}

