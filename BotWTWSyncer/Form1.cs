using System;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Globalization;
using PeNet;
using SharpDisasm.Udis86;
using System.Net;
using System.IO;
using Newtonsoft.Json.Linq;

namespace BotWTWSyncer
{
    public partial class Form1 : Form
    {

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32")]
        public extern static IntPtr LoadLibrary(string librayName);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        public static Process cemuProcess;

        public static IntPtr processHandle;

        public static long baseAddress;
        public static long realBaseAddress;

        public static long memoryBaseAddress;

        public string currentWeather;

        public static byte[] millisecsArray;

        public Form1()
        {
            InitializeComponent();
            numericUpDown1.Value = Properties.Settings.Default.Latitude;
            numericUpDown2.Value = Properties.Settings.Default.Longitude;
            checkBox2.Checked = Properties.Settings.Default.TimeSync;
            checkBox1.Checked = Properties.Settings.Default.WeatherSync;
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public bool getGameStartAddress()
        {
            PeFile peHeader = new PeNet.PeFile(cemuProcess.MainModule.FileName);

            foreach (ExportFunction exported in peHeader.ExportedFunctions)
            {
                if (exported.Name == null)
                {
                    break;
                }
                else if (exported.Name.Contains("memory_getBase"))
                {
                    memoryBaseAddress = (long)cemuProcess.MainModule.BaseAddress + checked((int)exported.Address);
                    int bytesRead = 0;
                    byte[] buffer = new byte[16];
                    IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, cemuProcess.Id);
                    ReadProcessMemory((int)processHandle, memoryBaseAddress, buffer, buffer.Length, ref bytesRead);

                    SharpDisasm.ArchitectureMode mode = SharpDisasm.ArchitectureMode.x86_64;

                    var disasm = new SharpDisasm.Disassembler(HexStringToByteArray(BitConverter.ToString(buffer).Replace("-", "")), mode, (ulong)memoryBaseAddress, false);
                    foreach (var insn in disasm.Disassemble())
                    {
                        if (insn.Operands[1].Type == ud_type.UD_OP_MEM && insn.Operands[1].Size == 64 && insn.Operands[1].Base == ud_type.UD_R_RIP && insn.Operands[1].Scale == 0 && insn.Operands[1].Index == ud_type.UD_NONE)
                        {
                            baseAddress = (long)(insn.PC + (ulong)insn.Operands[1].Value);

                            int bytesRead1 = 0;
                            byte[] buffer1 = new byte[8];

                            ReadProcessMemory((int)processHandle, baseAddress, buffer1, buffer1.Length, ref bytesRead1);
                            ulong bigLong = BitConverter.ToUInt64(buffer1, 0);
                            string converted = bigLong.ToString("X");
                            realBaseAddress = long.Parse(converted, NumberStyles.HexNumber);

                            break;
                        }
                    }
                }
            }

            return false;
        }

        public void createORconnect()
        {
            try {
                cemuProcess = Process.GetProcessesByName("Cemu")[0];
            } catch
            {
                MessageBox.Show("Cemu Emulator not found!");
                return;
            }

            try {
                getGameStartAddress();
            } catch
            {
                MessageBox.Show("An error has occured! Please try again!");
                return;
            }

            processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, cemuProcess.Id);


            byte[] gameRunningBytes = new byte[4];
            int bytesRead = 0;
            ReadProcessMemory((int)processHandle, realBaseAddress + 0xA00AF878, gameRunningBytes, gameRunningBytes.Length, ref bytesRead);

            if (BitConverter.ToString(gameRunningBytes) == "00-00-00-00")
            {
                MessageBox.Show("Breath of the Wild not Found!");
                return;
            }


            timer2.Enabled = true;
            timer1.Enabled = true;

            button6.Enabled = false;

            numericUpDown1.Enabled = false;
            numericUpDown2.Enabled = false;

            GetCurrentWeather();
        }

        private void button6_Click(object sender, EventArgs e)
        {
            createORconnect();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public void SetRealWeather()
        {
            byte[] weatherType = new byte[] { 0x00 };

            textBox1.Text = currentWeather;

            switch (currentWeather)
            {
                default:
                    weatherType = new byte[] { 0x00 };
                    break;
                case "Clouds":
                    weatherType = new byte[] { 0x01 };
                    break;
                case "Rain":
                    weatherType = new byte[] { 0x03 };
                    break;
            }

            int bytesRead = 0;
            WriteProcessMemory((int)processHandle, realBaseAddress + 0x3FF7DB24, weatherType, weatherType.Length, ref bytesRead);
        }

        public void SetRealTime()
        {
            TimeSpan fromMidnight = DateTime.Now - DateTime.Today;
            double millisecs = (fromMidnight.TotalMilliseconds / 86400000) * 360;

            float input = float.Parse(millisecs.ToString());
            byte[] buffer = BitConverter.GetBytes(input);
            int intVal = BitConverter.ToInt32(buffer, 0);
            string hexstring = intVal.ToString("X");

            millisecsArray = StringToByteArray(hexstring);

            int bytesRead = 0;
            WriteProcessMemory((int)processHandle, realBaseAddress + 0xA00AF878, millisecsArray, millisecsArray.Length, ref bytesRead);
        }

        public string GetFromURL(string uri)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        private void GetCurrentWeather()
        {
            string jsonString = GetFromURL("https://fcc-weather-api.glitch.me/api/current?lat=" + numericUpDown1.Value.ToString() + "&lon=" + numericUpDown2.Value.ToString());
            JObject jo = JObject.Parse(jsonString);

            string currentWeatherName = jo["weather"][0]["main"].ToString();

            currentWeather = currentWeatherName;
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            if (checkBox2.Checked)
            {
                SetRealTime();
            }
            if (checkBox1.Checked) {
                SetRealWeather();
            }
        }

        private void timer2_Tick(object sender, EventArgs e)
        {
            GetCurrentWeather();
        }

        public void VerifyNumericBoxes()
        {
            if ((numericUpDown1.Value == 0 || numericUpDown2.Value == 0) && checkBox1.Checked)
            {
                button6.Enabled = false;
            }
            else
            {
                button6.Enabled = true;
                Properties.Settings.Default.Latitude = numericUpDown1.Value;
                Properties.Settings.Default.Longitude = numericUpDown2.Value;
                Properties.Settings.Default.Save();
            }
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {
            VerifyNumericBoxes();
        }

        private void numericUpDown2_ValueChanged(object sender, EventArgs e)
        {
            VerifyNumericBoxes();
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("https://www.latlong.net/");
        }

        private void checkBox2_CheckStateChanged(object sender, EventArgs e)
        {
            Properties.Settings.Default.TimeSync = checkBox2.Checked;
            Properties.Settings.Default.Save();
        }

        private void checkBox1_CheckStateChanged(object sender, EventArgs e)
        {
            Properties.Settings.Default.WeatherSync = checkBox1.Checked;
            Properties.Settings.Default.Save();
            VerifyNumericBoxes();
        }
    }
}
