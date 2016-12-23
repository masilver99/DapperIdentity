using System;
using System.Data;
using System.Data.SqlClient;

namespace Silver.AspNetCore.Identity.Dapper
{
    /// <summary>
    /// A simple database connection manager
    /// </summary>
    public class DbContext : IDisposable
    {
        private IDbConnection _conn { get; set; }

        /// <summary>
        /// Return open connection
        /// </summary>
        public IDbConnection Connection
        {
            get
            {
                if (_conn.State == ConnectionState.Closed)
                    _conn.Open();

                return _conn;
            }
        }

        /// <summary>
        /// Create a new Sql database connection
        /// </summary>
        /// <param name="connString">The name of the connection string</param>
        public DbContext(string connString)
        {
            // Use first?
            if (connString == "")
                connString = "";//ConfigurationManager.ConnectionStrings[0].Name;

            _conn = new SqlConnection(connString);
        }

        /// <summary>
        /// Close and dispose of the database connection
        /// </summary>
        public void Dispose()
        {
            if (_conn != null)
            {
                if (_conn.State == ConnectionState.Open)
                {
                    _conn.Close();
                    _conn.Dispose();
                }
                _conn = null;
            }
        }
    }

}
