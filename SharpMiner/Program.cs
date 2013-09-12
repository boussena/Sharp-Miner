using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpMiner
{
    class Program
    {
        static void Main(string[] args)
        {
            int pcount;
            Miner mine;
            pcount = Environment.ProcessorCount;
            mine = new Miner();
            if (args.Length < 3) return;
            mine.go(args[0], args[1], args[2]);
        }
    }
}
