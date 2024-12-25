using JWT_Token.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Token.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]  // All actions require the user to be authenticated
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _context;

        public UsersController(AppDbContext context)
        {
            _context = context;
        }

        // Get all users - Available to any authenticated user
        [HttpGet]
        public IActionResult GetAll()
        {
            return Ok(_context.Users.ToList());
        }

        // Get user by ID - Available to any authenticated user
        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null)
                return NotFound("User not found.");

            return Ok(user);
        }

        // Create user - Available to any authenticated user
        [HttpPost]
        public IActionResult Create(User user)
        {
            _context.Users.Add(user);
            _context.SaveChanges();
            return CreatedAtAction(nameof(GetById), new { id = user.Id }, user);
        }

        // Update user - Available only to users with Admin role
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]  // Only Admin can update
        public IActionResult Update(int id, User user)
        {
            var existingUser = _context.Users.Find(id);
            if (existingUser == null)
                return NotFound("User not found.");

            existingUser.UserName = user.UserName;
            existingUser.Email = user.Email;
            existingUser.Password = user.Password;

            _context.SaveChanges();
            return Ok(new { message = $"User with ID {id} updated successfully." });
        }

        // Delete user - Available only to users with Admin role
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]  // Only Admin can delete
        public IActionResult Delete(int id)
        {
            var user = _context.Users.Find(id);
            if (user == null)
                return NotFound("User not found.");

            _context.Users.Remove(user);
            _context.SaveChanges();
            return Ok(new { message = $"User with ID {id} deleted successfully." });
        }
    }
}
