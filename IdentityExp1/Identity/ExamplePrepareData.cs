using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;

namespace NZ01
{
    public class ExamplePrepareData
    {
        public static void Init(
            UserManager<ExampleApplicationUser> userManager, 
            RoleManager<ExampleApplicationRole> roleManager)
        {
            ///////////////////////////////////////////////////////////////////
            // TEST DATA            
            // As this is a memory based Identity implementation, we have to
            // seed the "database" with users and roles for testing.


            // Populate Roles
            var role = new ExampleApplicationRole { RoleName = "Admin", RoleId = "Admin" };
            IdentityResult roleResult = roleManager.CreateAsync(role).Result;
            if (!roleResult.Succeeded) throw new Exception("Failed to create role Admin");

            role = new ExampleApplicationRole { RoleName = "User", RoleId = "User" };
            roleResult = roleManager.CreateAsync(role).Result;
            if (!roleResult.Succeeded) throw new Exception("Failed to create role User");


            // Populate Users
            var userAdmin = new ExampleApplicationUser { UserName = "Admin", Email = "admin@example.com" };
            if (!userManager.CreateAsync(userAdmin, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Admin");

            var userAlice = new ExampleApplicationUser { UserName = "Alice", Email = "alice@example.com" };
            if (!userManager.CreateAsync(userAlice, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Alice");

            var userBob = new ExampleApplicationUser { UserName = "Bob", Email = "bob@example.com" };
            if (!userManager.CreateAsync(userBob, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Bob");

            var userCharlie = new ExampleApplicationUser { UserName = "Charlie", Email = "charlie@example.com" };
            if (!userManager.CreateAsync(userCharlie, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Charlie");



            // Apply Roles 

            // Admin user is in [User,Admin] roles
            if (!userManager.AddToRoleAsync(userAdmin, "User").Result.Succeeded)
                throw new Exception("Failed to set role");

            if (!userManager.AddToRoleAsync(userAdmin, "Admin").Result.Succeeded)
                throw new Exception("Failed to set role");


            // Alice user is in [User] role
            if (!userManager.AddToRoleAsync(userAlice, "User").Result.Succeeded)
                throw new Exception("Failed to set role");


            // Bob is not in any role (sadface).

            // Charlie is purely an [Admin]
            if (!userManager.AddToRoleAsync(userCharlie, "Admin").Result.Succeeded)
                throw new Exception("Failed to set role");

            //
            ///////////////////////////////////////////////////////////////////
        }
    }
}
