using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

// Console subsystem is required: Chrome exchanges binary frames over redirected stdio.
internal static class BrowserHost
{
    private const string Origin = "chrome-extension://dinagdpfpgbcfepiaabjccimnppakedl/";
    private const string PipePrefix = @"\\.\pipe\private-vault-";
    private const int Limit = 256 * 1024;
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly object OutputLock = new object();
    private static readonly object PendingLock = new object();
    private static readonly Dictionary<string, Timer> Pending = new Dictionary<string, Timer>();
    private static Stream Output;
    private static NamedPipeClientStream Pipe;
    private static volatile bool Stopping;

    private static int Main(string[] args)
    {
        Output = Console.OpenStandardOutput();
        Stream input = Console.OpenStandardInput();
        if (args.Length == 1 && args[0] == "--protect-session") return ProtectSession(input);
        foreach (string arg in args) if (arg == "--protect-session") { input.Dispose(); Output.Dispose(); return 1; }
        string failure = null;
        string profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "private-vault");
        bool allowed = false;
        foreach (string arg in args)
        {
            if (arg == Origin) allowed = true;
            if (arg.StartsWith("--vault-profile-dir=", StringComparison.Ordinal))
            {
                string candidate = arg.Substring("--vault-profile-dir=".Length);
                if (!Path.IsPathRooted(candidate)) failure = "app_unavailable";
                else profile = Path.GetFullPath(candidate);
            }
        }
        if (!allowed) failure = "origin_forbidden";
        if (failure == null)
        {
            try
            {
                string file = Path.Combine(profile, "browser-session.json");
                if (new FileInfo(file).Length > 32768) throw new InvalidDataException();
                Dictionary<string, object> state = ObjectJson(File.ReadAllText(file, Utf8));
                if (!state.ContainsKey("v") || Convert.ToInt32(state["v"]) != 1) throw new InvalidDataException();
                string secret = StringValue(state, "secret");
                byte[] protectedBytes = Convert.FromBase64String(secret);
                if (Convert.ToBase64String(protectedBytes) != secret) throw new InvalidDataException();
                byte[] plain = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                Dictionary<string, object> session;
                try { session = ObjectJson(Utf8.GetString(plain)); }
                finally { Array.Clear(plain, 0, plain.Length); }
                string name = StringValue(session, "pipeName");
                string token = StringValue(session, "token");
                ValidateSession(session);
                string suffix = name.Substring(@"\\.\pipe\".Length);
                Pipe = new NamedPipeClientStream(".", suffix, PipeDirection.InOut, PipeOptions.Asynchronous);
                Pipe.Connect(4000);
                WriteFrame(Pipe, Utf8.GetBytes(Json(new Dictionary<string, object> { { "command", "hello" }, { "token", token } })));
                Thread pump = new Thread(PumpPipe);
                pump.IsBackground = true;
                pump.Start();
            }
            catch { failure = "app_unavailable"; if (Pipe != null) { Pipe.Dispose(); Pipe = null; } }
        }
        try
        {
            while (!Stopping)
            {
                byte[] body = ReadFrame(input);
                if (body == null) break;
                Dictionary<string, object> request;
                try { request = ObjectJson(Utf8.GetString(body)); }
                catch { SendError(null, "invalid_request"); continue; }
                string id = OptionalString(request, "requestId");
                string command = OptionalString(request, "command");
                if (id == null || !Regex.IsMatch(id, "^[A-Za-z0-9_-]{1,100}$") || command == null || command.Length == 0 || command.Length > 32)
                { SendError(id, "invalid_request"); continue; }
                if (failure != null) { SendError(id, failure); break; }
                bool accepted = false;
                string rejected = "busy";
                lock (PendingLock)
                {
                    if (Pending.ContainsKey(id)) rejected = "invalid_request";
                    else if (Pending.Count < 32)
                    {
                        Timer timer = new Timer(delegate { RequestExpired(id); }, null, System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
                        Pending.Add(id, timer);
                        timer.Change(12000, System.Threading.Timeout.Infinite);
                        accepted = true;
                    }
                }
                if (!accepted) { SendError(id, rejected); continue; }
                try { WriteFrame(Pipe, body); }
                catch { RemovePending(id); SendError(id, "app_unavailable"); Stop(); }
            }
        }
        catch { /* A broken or oversized frame closes the native port. */ }
        finally { Stop(); input.Dispose(); Output.Dispose(); }
        return 0;
    }

    private static int ProtectSession(Stream input)
    {
        byte[] body = null;
        try
        {
            body = ReadFrame(input, 32768);
            if (body == null || body.Length > 32768) throw new InvalidDataException();
            Dictionary<string, object> session = ObjectJson(Utf8.GetString(body));
            ValidateSession(session);
            // The short-lived pipe credential uses plain DPAPI rather than Chromium's AES v10 format.
            byte[] protectedBytes = ProtectedData.Protect(body, null, DataProtectionScope.CurrentUser);
            byte[] response = Utf8.GetBytes(Json(new Dictionary<string, object> { { "secret", Convert.ToBase64String(protectedBytes) } }));
            if (response.Length > 32768) throw new InvalidDataException();
            WriteFrame(Output, response);
            return 0;
        }
        catch { return 1; }
        finally { if (body != null) Array.Clear(body, 0, body.Length); input.Dispose(); Output.Dispose(); }
    }

    private static void ValidateSession(Dictionary<string, object> session)
    {
        string name = StringValue(session, "pipeName"), token = StringValue(session, "token");
        if (session.Count != 2 || !name.StartsWith(PipePrefix, StringComparison.Ordinal) || !Regex.IsMatch(token, "^[a-f0-9]{64}$")) throw new InvalidDataException();
        string suffix = name.Substring(@"\\.\pipe\".Length);
        if (!Regex.IsMatch(suffix, "^private-vault-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")) throw new InvalidDataException();
    }

    private static void PumpPipe()
    {
        try
        {
            while (!Stopping)
            {
                byte[] body = ReadFrame(Pipe);
                if (body == null) break;
                Dictionary<string, object> response = ObjectJson(Utf8.GetString(body));
                string id = OptionalString(response, "requestId");
                if (id != null && RemovePending(id)) Send(body);
            }
        }
        catch { }
        if (!Stopping)
        {
            string[] ids;
            lock (PendingLock) { ids = new string[Pending.Count]; Pending.Keys.CopyTo(ids, 0); }
            foreach (string id in ids) { if (RemovePending(id)) SendError(id, "app_unavailable"); }
            Stop();
            // Interrupt a Windows blocking stdin read when the tray app exits.
            Environment.Exit(0);
        }
    }

    private static void RequestExpired(string id)
    {
        if (RemovePending(id)) SendError(id, "request_timeout");
    }

    private static bool RemovePending(string id)
    {
        lock (PendingLock)
        {
            Timer timer;
            if (!Pending.TryGetValue(id, out timer)) return false;
            Pending.Remove(id); timer.Dispose(); return true;
        }
    }

    private static void Stop()
    {
        Stopping = true;
        lock (PendingLock) { foreach (Timer timer in Pending.Values) timer.Dispose(); Pending.Clear(); }
        if (Pipe != null) { try { Pipe.Dispose(); } catch { } }
    }

    private static byte[] ReadFrame(Stream stream, int limit = Limit)
    {
        byte[] head = new byte[4];
        int first = stream.Read(head, 0, 4);
        if (first == 0) return null;
        ReadRemaining(stream, head, first);
        uint size = (uint)head[0] | ((uint)head[1] << 8) | ((uint)head[2] << 16) | ((uint)head[3] << 24);
        if (size == 0 || size > limit) throw new InvalidDataException();
        byte[] body = new byte[(int)size];
        ReadRemaining(stream, body, 0);
        return body;
    }

    private static void ReadRemaining(Stream stream, byte[] bytes, int offset)
    {
        while (offset < bytes.Length)
        {
            int count = stream.Read(bytes, offset, bytes.Length - offset);
            if (count == 0) throw new EndOfStreamException();
            offset += count;
        }
    }

    private static void WriteFrame(Stream stream, byte[] body)
    {
        if (body.Length == 0 || body.Length > Limit) throw new InvalidDataException();
        byte[] head = new byte[] { (byte)body.Length, (byte)(body.Length >> 8), (byte)(body.Length >> 16), (byte)(body.Length >> 24) };
        stream.Write(head, 0, head.Length); stream.Write(body, 0, body.Length); stream.Flush();
    }

    private static void Send(byte[] body)
    {
        try { lock (OutputLock) { WriteFrame(Output, body); } }
        catch { Stop(); Environment.Exit(0); }
    }

    private static void SendError(string id, string code)
    {
        string message = code == "origin_forbidden" ? "此扩展未获准连接密码软件。" : code == "invalid_request" ? "浏览器请求格式无效。" : code == "busy" ? "浏览器操作过多，请稍后再试。" : code == "request_timeout" ? "密码软件响应超时，请重新核对后重试。" : "请打开密码软件，并启用浏览器助手。";
        Send(Utf8.GetBytes(Json(new Dictionary<string, object> { { "requestId", id }, { "ok", false }, { "error", new Dictionary<string, object> { { "code", code }, { "message", message } } } })));
    }

    private static JavaScriptSerializer Serializer()
    {
        return new JavaScriptSerializer { MaxJsonLength = Limit * 2, RecursionLimit = 64 };
    }
    private static string Json(object value) { return Serializer().Serialize(value); }
    private static Dictionary<string, object> ObjectJson(string value)
    {
        Dictionary<string, object> result = Serializer().DeserializeObject(value) as Dictionary<string, object>;
        if (result == null) throw new InvalidDataException();
        return result;
    }
    private static string OptionalString(Dictionary<string, object> value, string name)
    {
        object found; return value.TryGetValue(name, out found) ? found as string : null;
    }
    private static string StringValue(Dictionary<string, object> value, string name)
    {
        string result = OptionalString(value, name); if (result == null) throw new InvalidDataException(); return result;
    }
}
