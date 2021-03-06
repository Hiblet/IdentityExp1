-- Table Create Script for CustomIdentity

-- COMMENTS WIP
-- 1. Currently not happy with possibility of keys exceeding 900 byte
--    limit for some tables.  Convert them to use a private key that 
--    is a hash of the data, giving same functionality without 
--    exposure to the error.


-- DEVIATIONS FROM ASPNETCORE EF IDENTITY
--
--  AspNetUsers.LockoutEnd 
--    Changed from DateTimeOffset to an absolute DateTime in UTC.
--  AspNetUsers.CreatedTimestamp
--    Added column to record time of user creation in UTC.
--  AspNetUsers.UpdateTimestamp
--    Added column to record time of last update in UTC.
--  AspNetUsers.Enabled
--    Added column to enable or disable a user on demand.
--
--  AspNetRoles.CreatedTimestamp
--    Added column to record time of user creation in UTC.
--  AspNetRoles.UpdateTimestamp
--    Added column to record time of last update in UTC.
--
--  AspNetTokens: Custom Table for Storing local Jwt tokens


USE [CustomIdentity]
GO

-- Dropping constraints on tables...
--SELECT 
--    'ALTER TABLE [' +  OBJECT_SCHEMA_NAME(parent_object_id) +
--    '].[' + OBJECT_NAME(parent_object_id) + 
--    '] DROP CONSTRAINT [' + name + ']'
--FROM sys.foreign_keys
--WHERE referenced_object_id = object_id('AspNetUsers');
--GO

ALTER TABLE [dbo].[AspNetUserClaims] DROP CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId];
GO

ALTER TABLE [dbo].[AspNetUserLogins] DROP CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId];
GO

ALTER TABLE [dbo].[AspNetUserRoles] DROP CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId];
GO

ALTER TABLE [dbo].[AspNetRoleClaims] DROP CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId];
GO

ALTER TABLE [dbo].[AspNetUserRoles] DROP CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId];
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetUserLogins') IS NOT NULL DROP TABLE [dbo].[AspNetUserLogins]
GO
CREATE TABLE [dbo].[AspNetUserLogins](
	[LoginProvider] [nvarchar](450) NOT NULL,
	[ProviderKey] [nvarchar](450) NOT NULL,
	[ProviderDisplayName] [nvarchar](max) NULL,
	[UserId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetUserLogins] PRIMARY KEY CLUSTERED 
(
	[LoginProvider] ASC,
	[ProviderKey] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetUserClaims') IS NOT NULL DROP TABLE [dbo].[AspNetUserClaims]
GO
CREATE TABLE [dbo].[AspNetUserClaims](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[ClaimType] [nvarchar](max) NULL,
	[ClaimValue] [nvarchar](max) NULL,
	[UserId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetUserClaims] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetUserTokens') IS NOT NULL DROP TABLE [dbo].[AspNetUserTokens]
GO
CREATE TABLE [dbo].[AspNetUserTokens](
	[UserId] [nvarchar](450) NOT NULL,
	[LoginProvider] [nvarchar](450) NOT NULL,
	[Name] [nvarchar](450) NOT NULL,
	[Value] [nvarchar](max) NULL,	
 CONSTRAINT [PK_AspNetUserTokens] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[LoginProvider] ASC,
	[Name] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetTokens') IS NOT NULL DROP TABLE [dbo].[AspNetTokens]
GO
CREATE TABLE [dbo].[AspNetTokens](
	[Name] [nvarchar](450) NOT NULL,
	[IP] [nvarchar](64) NULL,
	[Guid] [nvarchar](450) NOT NULL,
	[CreatedTimestamp] [datetime] NOT NULL DEFAULT GETUTCDATE(),
	[UpdateTimestamp] [datetime] NOT NULL,
 CONSTRAINT [PK_AspNetTokens] PRIMARY KEY CLUSTERED 
(
	[Guid] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] --TEXTIMAGE_ON [PRIMARY]
GO


SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetUsers') IS NOT NULL DROP TABLE [dbo].[AspNetUsers]
GO
CREATE TABLE [dbo].[AspNetUsers](
	[Id] [nvarchar](450) NOT NULL,
	[UserName] [nvarchar](256) NULL,
	[AccessFailedCount] [int] NOT NULL,
	[ConcurrencyStamp] [nvarchar](max) NULL,
	[Email] [nvarchar](256) NULL,
	[EmailConfirmed] [bit] NOT NULL,
	[LockoutEnabled] [bit] NOT NULL,
	[LockoutEnd] [datetime] NULL,
	[NormalizedEmail] [nvarchar](256) NULL,
	[NormalizedUserName] [nvarchar](256) NULL,
	[PasswordHash] [nvarchar](max) NULL,
	[PhoneNumber] [nvarchar](max) NULL,
	[PhoneNumberConfirmed] [bit] NOT NULL,
	[SecurityStamp] [nvarchar](max) NULL,
	[TwoFactorEnabled] [bit] NOT NULL,
	[Enabled] [bit] NOT NULL,
	[CreatedTimestamp] [datetime] NOT NULL DEFAULT GETUTCDATE(),
	[UpdateTimestamp] [datetime] NOT NULL,
 CONSTRAINT [PK_AspNetUsers] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetRoles') IS NOT NULL DROP TABLE [dbo].[AspNetRoles]
GO
CREATE TABLE [dbo].[AspNetRoles](
	[Name] [nvarchar](256) NULL,
	[Id] [nvarchar](450) NOT NULL,
	[ConcurrencyStamp] [nvarchar](max) NULL,
	[NormalizedName] [nvarchar](256) NULL,
	[CreatedTimestamp] [datetime] NOT NULL DEFAULT GETUTCDATE(),
	[UpdateTimestamp] [datetime] NOT NULL,
 CONSTRAINT [PK_AspNetRoles] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetRoleClaims') IS NOT NULL DROP TABLE [dbo].[AspNetRoleClaims]
GO
CREATE TABLE [dbo].[AspNetRoleClaims](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[ClaimType] [nvarchar](max) NULL,
	[ClaimValue] [nvarchar](max) NULL,
	[RoleId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetRoleClaims] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
IF OBJECT_ID('dbo.AspNetUserRoles') IS NOT NULL DROP TABLE [dbo].[AspNetUserRoles]
GO
CREATE TABLE [dbo].[AspNetUserRoles](
	[UserId] [nvarchar](450) NOT NULL,
	[RoleId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetUserRoles] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO


ALTER TABLE [dbo].[AspNetRoleClaims]  WITH CHECK ADD  CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId] FOREIGN KEY([RoleId])
REFERENCES [dbo].[AspNetRoles] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetRoleClaims] CHECK CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId]
GO

ALTER TABLE [dbo].[AspNetUserClaims]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserClaims] CHECK CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId]
GO

ALTER TABLE [dbo].[AspNetUserLogins]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserLogins] CHECK CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId]
GO

ALTER TABLE [dbo].[AspNetUserRoles]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId] FOREIGN KEY([RoleId])
REFERENCES [dbo].[AspNetRoles] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserRoles] CHECK CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId]
GO

ALTER TABLE [dbo].[AspNetUserRoles]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserRoles] CHECK CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId]
GO


-- STORED PROCEDURES

IF EXISTS (SELECT * FROM sysobjects WHERE  
  id = object_id(N'[dbo].[UpdateUserWithConcurrencyStamp]') 
  and OBJECTPROPERTY(id, N'IsProcedure') = 1 )
BEGIN
    DROP PROCEDURE [dbo].[UpdateUserWithConcurrencyStamp]
END
GO
CREATE PROCEDURE UpdateUserWithConcurrencyStamp
	@userId nvarchar(450),
	@updateTimestamp datetime,
	@accessFailedCount int,
	@concurrencyStamp nvarchar(max),
	@email nvarchar(256),
	@emailNormalized nvarchar(256),
	@emailConfirmed bit,
	@lockoutEnabled bit,
	@lockoutEnd datetime,
	@passwordHash nvarchar(max),
	@phoneNumber nvarchar(max),
	@phoneNumberConfirmed bit,
	@securityStamp nvarchar(max),
	@twoFactorEnabled bit,
	@enabled bit
AS
BEGIN
	DECLARE @extantConcurrencyStamp nvarchar(max);
	SET @extantConcurrencyStamp = 
	(
		SELECT [ConcurrencyStamp] 
		FROM [dbo].[AspNetUsers] 
		WHERE [Id] = @userId
	);
	IF @extantConcurrencyStamp = @concurrencyStamp
		UPDATE [dbo].[AspNetUsers] SET 
			[ConcurrencyStamp] = NEWID(),
			[AccessFailedCount] = @accessFailedCount,
			[Email] = @email,
			[EmailConfirmed] = @emailConfirmed,
			[NormalizedEmail] = @emailNormalized,
			[LockoutEnabled] = @lockoutEnabled,
			[LockoutEnd] = @lockoutEnd,
			[PasswordHash] = @passwordHash,
			[PhoneNumber] = @phoneNumber,
			[PhoneNumberConfirmed] = @phoneNumberConfirmed,
			[SecurityStamp] = @securityStamp,
			[TwoFactorEnabled] = @twoFactorEnabled,
			[Enabled] = @enabled
		WHERE [Id] = @userId;	
END
GO
	


