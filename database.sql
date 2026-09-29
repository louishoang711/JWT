IF DB_ID(N'JWT') IS NULL
BEGIN
    CREATE DATABASE [JWT];
END;
GO

USE [JWT];
GO

-- Hibernate creates/updates the users table because spring.jpa.hibernate.ddl-auto=update.
