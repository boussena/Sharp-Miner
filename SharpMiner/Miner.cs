using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.Net.Security;
using System.IO;
using System.Web;
using System.Collections;
using Replicon.Cryptography.SCrypt;
using System.Threading;
class Miner
{
    //============================General Variables===============================
    bool done = false;
    uint fnonce = 0;
    public double hashspeed = 0;
    public string logs = "";
    string longpooling = null;
    int hr = 0;
    int elapsedtime = 0;
    int shresubmitted = 0;
    int sharesaccepted = 0;
    DateTime D0 = DateTime.Now;
    public Miner()
    { 
        hashspeed = 0;
        LP = new Thread(() => newblock("", ""));
    }
    int READ_TIMEOUT = 30 * 60 * 1000; // ms
    Thread[] ths;
    Thread LP;
    int i = 0;
    static char[] BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToCharArray();
    //===================Main=====================================================2, 2
    public void go(string url, string user, string pass)
    {
        object args = new object[3] { user,pass,url };
        while (true)
        {
            try
            {
                int pcount = Environment.ProcessorCount;
                ths = new Thread[pcount];
                Go(args);
            }
            catch (Exception Ex)
            { Console.WriteLine(Ex); }
        }
    }

    //============================================================================
    public void doScrypt(object args)
    {
        Array argArray = new object[4];
        argArray = (Array)args;
        byte[] tdatabyte=(byte[])argArray.GetValue(0);
        byte[] databyte = new byte[80];
        Array.Copy(tdatabyte, 0, databyte, 0, 76);
        byte[] target=(byte[])argArray.GetValue(1);
        uint nonce = (uint)argArray.GetValue(2);
        uint x = (uint)argArray.GetValue(3);
        
        byte[] voide = new byte[4];
        try
        {
            
            
            
            byte[] scrypted = new byte[32];
            //Loop over and increment nonce
            while (!done )
            {
                databyte[76] = (byte)(nonce >> 0);
                databyte[77] = (byte)(nonce >> 8);
                databyte[78] = (byte)(nonce >> 16);
                databyte[79] = (byte)(nonce >> 24);
                scrypted = SCrypt.DeriveKey(databyte, databyte, 1024, 1, 1, 32);
                
                hr++;
                if (meetsTarget(scrypted, target))
                {
                    if(!done)fnonce = nonce; done = true; break;
                }
                else
                    nonce+=x; //Otherwise increment the nonce

                elapsedtime=(DateTime.Now - D0).Milliseconds;
                if (longpooling==null&&elapsedtime >= 1) { done = true; break; }
            }
        }
        catch (Exception ex)
        { Console.WriteLine(ex); fnonce = 0; }
    }
    //============================================================================
    public void Go(object args)
    {
            Array argArray = new object[3];
            argArray = (Array)args;
            string user = (string)argArray.GetValue(0);
            string pass = (string)argArray.GetValue(1);
            string url = (string)argArray.GetValue(2);

            i++;
            string cred = user + ":" + pass;
            string resp = getwork(url, cred);
            
            var ada = (Hashtable)JSON.JsonDecode(resp);
            var adata = (Hashtable)ada["result"];
            //Gets the data to hash from the work
            string data = adata["data"].ToString(); 
            byte[] databyte = headerByData(HexStringToBytes(data));
            //Gets the target from the work
            string target = adata["target"].ToString(); ;
            byte[] targetbyte = HexStringToBytes(target);
        //===================================Brute Force Attack====================================(int)(int.MaxValue / ths.Length) * ii
            done = false;
            fnonce = 0;
            hr = 0;
            D0 = DateTime.Now;
            elapsedtime = 0;
            for (int ii = 0; ii < ths.Length; ii++)
            {
                object argss = new object[4] { databyte, targetbyte, (uint)ii, (uint)ths.Length };
                ths[ii] = new Thread(() => doScrypt(argss));
                ths[ii].IsBackground = true;
                //ths[ii].Priority = ThreadPriority.Lowest;
                ths[ii].Start();
            }
            if (longpooling != null && LP.ThreadState != ThreadState.Running)
            {
                LP = new Thread(() => newblock(url + longpooling, cred));
                LP.Start();
            }
            while (!done) Thread.Sleep(5);
            hashspeed = (double)hr / elapsedtime;
            Console.WriteLine("Speed: "+(int)(hashspeed) +"KHash/Second!");
        //==================================Sumit if work done!=======================================
            if (fnonce != 0)
            {
                byte[] databyte2 = HexStringToBytes(data);
                databyte2[79] = (byte)(fnonce >> 0);
                databyte2[78] = (byte)(fnonce >> 8);
                databyte2[77] = (byte)(fnonce >> 16);
                databyte2[76] = (byte)(fnonce >> 24);
                submit(url, cred, HexToString(databyte2));

            }
    }
    public bool meetsTarget(byte[] hash, byte[] target)
    {
        for (int i = hash.Length - 1; i >= 0; i--)
        {
            if ((hash[i] & 0xff) > (target[i] & 0xff))
                return false;
            if ((hash[i] & 0xff) < (target[i] & 0xff))
                return true;
        }
        return false;
    }
    //============================================================================
    //============================================================================
    public string HexToString(byte[] ba)
    {
        StringBuilder sb = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
        {
            sb.AppendFormat("{0:x2}", b);
        }
        return sb.ToString();
    }
    //============================================================================
    public byte[] HexStringToBytes(string hex)
    {
        byte[] data = new byte[hex.Length / 2];
        int j = 0;
        for (int i = 0; i < hex.Length; i += 2)
        {
            data[j] = Convert.ToByte(hex.Substring(i, 2), 16);
            ++j;
        }
        return data;
    }
    //============================================================================
    public static String stringToBase64(String str)
    {
        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding(); 
        byte[] buf = encoding.GetBytes(str);
        int size = buf.Length;
        char[] ar = new char[((size + 2) / 3) * 4];
        int a = 0;
        int i = 0;
        while (i < size)
        {
            byte b0 = buf[i++];
            byte b1 =(byte) ((i < size) ? buf[i++] : 0);
            byte b2 = (byte) ((i < size) ? buf[i++] : 0);
            ar[a++] = BASE64_ALPHABET[(b0 >> 2) & 0x3f];
            ar[a++] = BASE64_ALPHABET[((b0 << 4) | ((b1 & 0xFF) >> 4)) & 0x3f];
            ar[a++] = BASE64_ALPHABET[((b1 << 2) | ((b2 & 0xFF) >> 6)) & 0x3f];
            ar[a++] = BASE64_ALPHABET[b2 & 0x3f];
        }
        int o=0;
        switch (size % 3)
        {
            case 1: ar[--a] = '='; break;
            case 2: ar[--a] = '='; break;
        }
        return new String(ar);
    }
    //============================================================================
    private string getwork(string url, string Credentials)
    {
        Dictionary<string, string> inj = new Dictionary<string, string>();
        HttpWebRequest rq = (HttpWebRequest)WebRequest.Create(url);
        String request = "{\"method\": \"getwork\", \"params\": [], \"id\":0}";
        byte[] byteArray = Encoding.UTF8.GetBytes(request);
        rq.Headers.Add("Authorization", "Basic " + stringToBase64(Credentials));
        rq.ContentType = "application/json-rpc";
        rq.ContentLength = byteArray.Length;
        rq.Method = "POST";
        rq.Headers.Add("X-Mining-Extensions", "midstate");
        using (Stream dataStream = rq.GetRequestStream())
        { dataStream.Write(byteArray, 0, byteArray.Length); }
        string res;
        using (WebResponse webResponse = rq.GetResponse())
        {
            using (Stream str = webResponse.GetResponseStream())
            {
                using (StreamReader sr = new StreamReader(str))
                {
                    res = sr.ReadToEnd();
                }
            }
            longpooling = webResponse.Headers["X-Long-Polling"];
        }
        return res;
    }
    private void newblock(string url,string c)
    {
        Dictionary<string, string> inj = new Dictionary<string, string>();
        HttpWebRequest rq = (HttpWebRequest)WebRequest.Create(url);
        String request = "{\"method\": \"getwork\", \"params\": [], \"id\":0}";
        byte[] byteArray = Encoding.UTF8.GetBytes(request);
        rq.Headers.Add("Authorization", "Basic " + stringToBase64(c));
        rq.ContentType = "application/json-rpc";
        rq.ContentLength = byteArray.Length;
        rq.Method = "POST";
        rq.Timeout = READ_TIMEOUT;
        rq.Headers.Add("X-Mining-Extensions", "midstate");
        using (Stream dataStream = rq.GetRequestStream())
        { dataStream.Write(byteArray, 0, byteArray.Length); }
        string res;
        try
        {
            using (WebResponse webResponse = rq.GetResponse())
            {
                using (Stream str = webResponse.GetResponseStream())
                {
                    using (StreamReader sr = new StreamReader(str))
                    {
                        res = sr.ReadToEnd();
                    }
                }
            }
            done = true;
            Console.WriteLine("New Block Deteted!");
        }
        catch (System.Exception e) {  }
        done = true;
    }
    //============================================================================
    private string submit(string url, string Credentials, string data)
    {
        Dictionary<string, string> inj = new Dictionary<string, string>();
        HttpWebRequest rq = (HttpWebRequest)WebRequest.Create(url);
        rq.Headers.Add("Authorization", "Basic " + stringToBase64(Credentials));
        rq.ContentType = "application/json-rpc";
        rq.Method = "POST";
        rq.Headers.Add("X-Mining-Extensions", "midstate");
        String request = "{\"method\": \"getwork\", \"params\": [ \"" + data + "\" ], \"id\":1}";
        byte[] byteArray = Encoding.UTF8.GetBytes(request);
        rq.ContentLength = byteArray.Length;
        using (Stream dataStream = rq.GetRequestStream()) { dataStream.Write(byteArray, 0, byteArray.Length); }
        string res;
        using (WebResponse webResponse = rq.GetResponse())
        {

            using (Stream str = webResponse.GetResponseStream())
            {
                using (StreamReader sr = new StreamReader(str))
                {
                    res = sr.ReadToEnd();
                }
            }
        }
        shresubmitted++;
        if (res.Contains("\"result\": true"))
        {
            sharesaccepted++;
            Console.WriteLine("Share Accepted! " + sharesaccepted+"/"+shresubmitted);
        }
        else Console.WriteLine("Share Denied! " + sharesaccepted + "/" + shresubmitted);
        return res;
    }
    //============================================================================
    private static byte[] headerByData(byte[] data)
    {
        byte[] h = new byte[80];
        for (int i = 0; i < 80; i += 4)
        {
            h[i] = data[i + 3];
            h[i + 1] = data[i + 2];
            h[i + 2] = data[i + 1];
            h[i + 3] = data[i];
        }
        return h;
    }
    //============================================================================
    private string log(byte[] data, byte[] hash)
    {
        string s = "";
        for (int i = 0; i < data.Length; i ++)
        {
            s += map((double)data[i], 0, 255, 0, 1).ToString() + " ";
        }
        for (int i = 0; i < hash.Length; i++)
        {
            s += map((double)hash[i],0,255,0,1).ToString() + " ";
        }
        s += "\r\n";
        return s;

    }
    //============================================================================
    public double map(double x, double in_min, double in_max, double out_min, double out_max)
    {
        return ((x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min);
    }
    //============================================================================
    //============================================================================
}
