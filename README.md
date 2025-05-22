https://promptcoder.it.com/

# AI-Powered Code Generator and Collaborator

## Project Overview

AI-Powered Code Generator and Collaborator is a modern web application that leverages OpenAI's API to assist developers in generating, modifying, and collaborating on code snippets in real-time. The platform features a robust FastAPI backend, an intuitive Angular frontend, a PostgreSQL database for user management, secure user authentication, and real-time collaboration capabilities to enhance productivity and teamwork.

## Key Features

- **AI-Driven Code Generation & Modification:** Utilize OpenAI's API to generate and modify code snippets seamlessly.
- **User Authentication & Authorization:** Secure login, registration, and role-based access control.
- **Real-Time Collaboration:** Multiple users can collaborate on code snippets simultaneously.
- **Secure Data Storage:** PostgreSQL database to manage users, sessions, and code snippets.
- **Responsive Angular UI:** Intuitive and responsive interface for a smooth user experience.
- **API Gateway & Proxy:** Secure and efficient API routing with middleware support.
- **Encryption & Security:** RSA encryption for secure token handling.

## Technology Stack

- **Backend:** FastAPI (Python 3.11)
- **Frontend:** Angular (latest stable)
- **Database:** PostgreSQL
- **AI API:** OpenAI API
- **Authentication:** OAuth2, JWT, RSA encryption
- **Deployment & CI/CD:** Docker, Docker Compose, GitHub Actions
- **Web Server:** Nginx
- **Others:** Starlette middleware, httpx, cryptography, SQLAlchemy, databases

## Setup Instructions

### Prerequisites

- Docker & Docker Compose installed
- Python 3.11 installed
- Node.js and npm installed
- PostgreSQL server running
- OpenAI API key

### Backend Setup

1. Clone the repository:

```bash
git clone <your-repo-url>
cd your-repo
```

2. Configure environment variables:

Create a `.env` file in the root with your database credentials and OpenAI API key:

```env
DATABASE_URL=postgresql://user:password@localhost/dbname
OPENAI_API_KEY=your-openai-api-key
SECRET_KEY=your-secret-key
```

3. Build and run the backend:

```bash
cd backend
pip install -r requirements.txt
# Ensure PostgreSQL is running and accessible
# Run database migrations if needed
# For development, you can use uvicorn:
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

1. Navigate to the frontend directory:

```bash
cd ../frontend
```

2. Install dependencies:

```bash
npm install
```

3. Build and serve the Angular app:

```bash
ng serve --open
```

### Docker Setup

Alternatively, you can use Docker Compose to run the entire stack:

```bash
docker-compose up --build
```

Ensure your environment variables are correctly set in the `.env` file for Docker.

## Example Usage

- Register a new user via the registration endpoint or frontend.
- Log in to receive a JWT token.
- Use the token to access protected routes, generate code snippets, or collaborate.
- Access the real-time collaboration interface to work with others.
- Generate encrypted JWTs via `/generate-rsa-jwt` and verify via `/verify-rsa-jwt` endpoints.

## Additional Notes

- The application uses RSA encryption for secure token handling.
- Middleware proxies requests to internal APIs, ensuring security and scalability.
- The project is configured for CI/CD with GitHub Actions, automating testing and deployment.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

For further assistance, refer to the detailed documentation in the `/docs` directory or contact the project maintainers.
