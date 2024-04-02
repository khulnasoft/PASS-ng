using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace winPEAS.Tests
{
    [TestClass]
    public class SmokeTests
    {
        [TestMethod]
        public void ShouldRunWinPass()
        {
            try
            {
                string[] args = new string[] { "systeminfo", "userinfo", "networkinfo", "servicesinfo","processinfo" };
                Program.Main(args);
            }
            catch (Exception e)
            {
                Assert.Fail($"Exception thrown: {e.Message}");
            }
        }
    }
}

