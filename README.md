# Authentication App

A full-stack authentication application built with Rust (backend) and React (frontend).

## Features

- User registration with email and password
- User login with JWT token authentication
- Password hashing using Argon2 (more secure than bcrypt)
- Protected routes requiring authentication
- PostgreSQL database
- Modern React frontend with clean UI

## Tech Stack

### Backend
- **Rust** with Axum web framework
- **PostgreSQL** database
- **SQLx** for database interactions
- **JWT** (jsonwebtoken) for authentication
- **Argon2** for password hashing
- **Tower-HTTP** for CORS

### Frontend
- **React** with Vite
- **localStorage** for token persistence
- Modern CSS with gradient backgrounds

## Prerequisites

- Rust (latest stable version)
- Node.js and npm
- PostgreSQL database (or use the Railway PostgreSQL instance)

## Setup Instructions

### Backend Setup

1. Navigate to the server directory:
```bash
cd server
```

2. The `.env` file is already configured with your Railway PostgreSQL credentials. If you need to change it, edit `server/.env`:
```
DATABASE_URL=postgresql://user:password@host:port/database
JWT_SECRET=your-secret-key-here
SERVER_PORT=3000
```

3. Install dependencies and run the server:
```bash
cargo run
```

The server will:
- Connect to PostgreSQL
- Run database migrations automatically
- Start on http://localhost:3000

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will start on http://localhost:5173

## API Endpoints

### Public Endpoints
- `POST /api/register` - Register a new user
  ```json
  {
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123"
  }
  ```

- `POST /api/login` - Login existing user
  ```json
  {
    "email": "john@example.com",
    "password": "password123"
  }
  ```

### Protected Endpoints
- `GET /api/me` - Get current user info (requires Bearer token)
  - Header: `Authorization: Bearer <your-jwt-token>`

### Health Check
- `GET /api/health` - Check if server is running

## How It Works

### Registration Flow
1. User enters username, email, and password
2. Backend hashes password with Argon2
3. User is created in PostgreSQL database
4. JWT token is generated and returned
5. Frontend stores token in localStorage

### Login Flow
1. User enters email and password
2. Backend verifies credentials
3. Password is verified using Argon2
4. JWT token is generated and returned
5. Frontend stores token in localStorage

### Authentication Flow
1. Frontend sends JWT token in Authorization header
2. Backend middleware validates token
3. If valid, user info is extracted and passed to endpoint
4. Protected endpoint returns user data

## Security Features

- **Argon2** password hashing (winner of Password Hashing Competition)
- **JWT** tokens with 24-hour expiration
- **CORS** enabled for cross-origin requests
- **Password validation** (minimum 6 characters)
- **Unique constraints** on username and email
- **SQL injection protection** via SQLx parameterized queries

## Project Structure

```
authentication_app/
├── server/
│   ├── src/
│   │   └── main.rs          # Backend server code
│   ├── migrations/
│   │   └── 20250115000001_create_users_table.sql
│   ├── Cargo.toml           # Rust dependencies
│   ├── .env                 # Environment variables
│   └── .env.example         # Example environment variables
└── frontend/
    ├── src/
    │   ├── App.jsx          # Main React component
    │   ├── App.css          # Styles
    │   ├── main.jsx         # React entry point
    │   └── index.css        # Global styles
    ├── package.json         # Node dependencies
    └── vite.config.js       # Vite configuration
```

## Learning Resources

This project demonstrates:
- RESTful API design
- JWT authentication
- Password hashing best practices
- Database migrations
- CORS configuration
- React state management
- localStorage usage
- Protected routes
- Error handling
- Form validation

## Next Steps

To enhance this project, you could add:
- Email verification
- Password reset functionality
- Refresh tokens
- Role-based access control (RBAC)
- User profile management
- Password strength meter
- Rate limiting
- Session management
- 2FA (Two-Factor Authentication)

## Troubleshooting

**Backend won't start:**
- Check PostgreSQL connection
- Verify DATABASE_URL in .env
- Ensure PostgreSQL server is running

**Frontend can't connect:**
- Make sure backend is running on port 3000
- Check browser console for CORS errors
- Verify API_URL in frontend/src/App.jsx

**Database errors:**
- Check if migrations ran successfully
- Verify database credentials
- Check database permissions

## License

MIT
