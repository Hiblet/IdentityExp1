USE [master]
GO

IF  EXISTS (SELECT name FROM sys.databases WHERE name = N'CustomIdentity')
DROP DATABASE [CustomIdentity]
GO

USE [master]
GO

CREATE DATABASE [CustomIdentity] ON  PRIMARY 
( NAME = N'CustomIdentity', FILENAME = N'c:\Program Files\Microsoft SQL Server\MSSQL10_50.SQLEXPRESS\MSSQL\DATA\CustomIdentity.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'CustomIdentity_log', FILENAME = N'c:\Program Files\Microsoft SQL Server\MSSQL10_50.SQLEXPRESS\MSSQL\DATA\CustomIdentity_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO

-- IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
-- begin
-- EXEC [CustomIdentity].[dbo].[sp_fulltext_database] @action = 'enable'
-- end
-- GO

-- If a column's null status is not specified, this default is used.
-- OFF implies NOT NULL, ON implies NULL.
ALTER DATABASE [CustomIdentity] SET ANSI_NULL_DEFAULT OFF 
GO

-- ON: Comparisons with null evaluate to UNKNOWN.
-- OFF: Comparisons (of non unicode values) with null evaluate to TRUE if both values are null.
ALTER DATABASE [CustomIdentity] SET ANSI_NULLS OFF 
GO

-- Effects trailing whitespace and binary value trailing zeros.
-- ON: Trailing whitespace is not trimmed; values are not padded to the column width.
-- OFF: Trailing blanks are trimmed.
ALTER DATABASE [CustomIdentity] SET ANSI_PADDING OFF 
GO

-- Effects divide-by-zero errors and NULLS in aggregates.
-- ON: Warnings are issued.
-- OFF: No warnings are issued.
ALTER DATABASE [CustomIdentity] SET ANSI_WARNINGS OFF 
GO

-- Effects arithmetic errors like divide-by-zero or overflow.
-- ON: Query is ended on error.
-- OFF: Query continues after error, but warnings are issued.
ALTER DATABASE [CustomIdentity] SET ARITHABORT OFF 
GO

-- ON: On last user exit, database is shutdown cleanly and resources released.
-- OFF: Leave resources in place.  
-- Ref: http://sqlmag.com/blog/worst-practice-allowing-autoclose-sql-server-databases
ALTER DATABASE [CustomIdentity] SET AUTO_CLOSE OFF
GO

-- ON: Allows SQL to self-optimise queries
ALTER DATABASE [CustomIdentity] SET AUTO_CREATE_STATISTICS ON 
GO

-- OFF: Deal with trans logs manually
ALTER DATABASE [CustomIdentity] SET AUTO_SHRINK OFF 
GO

-- ON: Allows SQL to update stats for self-optimised queries
ALTER DATABASE [CustomIdentity] SET AUTO_UPDATE_STATISTICS ON 
GO

-- OFF: No strong feelings, left on default.
ALTER DATABASE [CustomIdentity] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO

-- GLOBAL: Allows cursor to be referenced in any SP or batch on this connection.
ALTER DATABASE [CustomIdentity] SET CURSOR_DEFAULT  GLOBAL 
GO

-- Effects situation where one of two operands is NULL in a concatenation.
-- ON: Result of concatenation is null if either value is null.
-- OFF: Result is same as if null operand was an empty string, ie Non-null operand unchanged.
ALTER DATABASE [CustomIdentity] SET CONCAT_NULL_YIELDS_NULL OFF 
GO

-- Effects the situation where a numeric value loses precision and is rounded automatically.
-- ON: An error is generated on loss of precision.
-- OFF: No error occurs, rounded value is used or stored.
ALTER DATABASE [CustomIdentity] SET NUMERIC_ROUNDABORT OFF 
GO

-- Effects SQL Identifiers ie names of tables, databases, variables etc.
-- ON: Identifiers may be quoted.
-- OFF: Identifiers may not be quoted and must follow standard TSQL rules.
ALTER DATABASE [CustomIdentity] SET QUOTED_IDENTIFIER OFF 
GO

-- Effects AFTER Triggers, 
-- ON: Recursive triggering of after triggers is allowed.
-- OFF: Recursive triggering of after triggers is not allowed.
ALTER DATABASE [CustomIdentity] SET RECURSIVE_TRIGGERS OFF 
GO

-- SERVICE BROKER allows communication between databases to split tasks
-- ENABLE_BROKER: Default
ALTER DATABASE [CustomIdentity] SET  ENABLE_BROKER 
GO

-- ON/OFF
-- Ref: https://www.mssqltips.com/sqlservertip/2904/sql-servers-auto-update-statistics-async-option/
ALTER DATABASE [CustomIdentity] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO

-- OFF: Default; Relates to PK/FK date correlation 
ALTER DATABASE [CustomIdentity] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO

-- OFF: On would allow an impersonation context to access data outside database
ALTER DATABASE [CustomIdentity] SET TRUSTWORTHY OFF 
GO

-- Relevant only to transactions...
-- ON: Transactions are allowed to specify the isolation level, and may 
--     set it to snapshot, so that a snapshot is taken of all data before
--     the transaction is run.
-- OFF: Transactions may not specify the isolation level.
ALTER DATABASE [CustomIdentity] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO

-- SIMPLE: Queries parameterised based on default settings of the database.
-- FORCED: All Queries are parameterised.
ALTER DATABASE [CustomIdentity] SET PARAMETERIZATION SIMPLE 
GO

-- ON: A transaction specifying READ_COMMITTED isolation level will use
--     row versioning instead of locking.  At this isolation level, all
--     statements in the transaction see data in a snapshot as it is at
--     the start of the transaction.
-- OFF: Transactions specifying READ_COMMMITTED isolation level use locking.
ALTER DATABASE [CustomIdentity] SET READ_COMMITTED_SNAPSHOT ON 
GO

ALTER DATABASE [CustomIdentity] SET HONOR_BROKER_PRIORITY OFF 
GO

-- Standard RW database
ALTER DATABASE [CustomIdentity] SET  READ_WRITE 
GO

-- SIMPLE: Trans logs are truncated, meaning you might lose data if hard disks fail
-- FULL/BULK-LOGGED: You need a plan to backup trans logs periodically.
ALTER DATABASE [CustomIdentity] SET RECOVERY SIMPLE 
GO

-- Standard multi user access by grant
ALTER DATABASE [CustomIdentity] SET  MULTI_USER 
GO

-- CHECKSUM: A checksum is used to validate read/writes to disk.  This protects the data from corruption whilst on disk.
-- TORN-PAGE-DETECTION: Form of checksum based on bits.
-- NONE: No page verification, data may corrupt on disk and stuff your database, but it might run slightly faster.
ALTER DATABASE [CustomIdentity] SET PAGE_VERIFY CHECKSUM  
GO

-- OFF: Default, do not allow cross database ownership chaining.
ALTER DATABASE [CustomIdentity] SET DB_CHAINING OFF 
GO


