using System;
using System.Diagnostics;
using System.Timers;

namespace BDCrashAlerterService
{
    class Program
    {
        static void Main(string[] args)
        {
            var secondsInterval = 20;

            try
            {
                if (args.Length > 0)
                    int.TryParse(args[0], out secondsInterval);
            }
            catch (Exception) { }

            Console.WriteLine(CheckIfRunningOrConnected());

            Timer timer = new Timer();
            timer.Interval = secondsInterval * 1000;
            timer.Elapsed += Timer_Elapsed;
            timer.Start();

            while (Console.Read() != 'q') ;
        }

        private static void Timer_Elapsed(object sender, ElapsedEventArgs e)
        {
            Console.WriteLine(CheckIfRunningOrConnected());
        }

        static string CheckIfRunningOrConnected()
        {
            if (!IsBlackDesertRunning())
                return "crashed";
            else if (!IsBlackDesertConnected())
                return "disconnected";

            return "ok";
        }

        static bool IsBlackDesertRunning()
        {
            try
            {
                var blackDesert64Process = Process.GetProcessesByName("BlackDesert64");
                var blackDesert32Process = Process.GetProcessesByName("BlackDesert");

                return (blackDesert64Process != null || blackDesert32Process != null);
            }
            catch (Exception) { }
            return false;
        }

        static bool IsBlackDesertConnected()
        {
            try
            {
                var connections = IPHelper.GetActiveConnections();

                foreach (var connection in connections)
                {
                    if (connection.SourceProcess != null && connection.SourceProcess.ProcessName.Contains("BlackDesert"))
                        return true;
                }

                return false;
            }
            catch (Exception) { }
            return false;
        }
    }


}
