# DapperIdentity
Code for replacing EntityFramework with Dapper for Identity 2.1 Core - Many people aren't interested in using the Entity Framework in their pojects and Microsoft makes that difficult with only providing an EF option for Identity. However, my hats off to Microsoft for providing the source to EF Identity Core (https://github.com/aspnet/Identity/tree/dev/src/Microsoft.AspNetCore.Identity.EntityFrameworkCore)

This project is currently building in Visual Studio 2015 but is untested beyond that.

Most of the queries are for Postgres.  Will need to add a way to allow differences in SQL, perhaps a base list of SQL constants and each database can override.  One such query is upserts.  These can vary from DB to DB.
