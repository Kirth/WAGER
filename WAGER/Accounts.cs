using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAGER
{
    class Account
    {
        public string Identity;
        public bool Banned;
        public string Password; // replace with S & precalculated V
    }

    interface IAccountProvider
    {
        Account FindAccount(string identity);
    }

    class TempAccountProvider : IAccountProvider
    {
        List<Account> accounts = new List<Account>();

        public TempAccountProvider()
        {
            accounts.Add(new Account() { Identity = "KIRTH", Banned = false, Password = "PONY" });
        }
        public Account FindAccount(string identity)
        {
            return accounts.Where((c) => c.Identity == identity).FirstOrDefault(); 
        }
    }
}
