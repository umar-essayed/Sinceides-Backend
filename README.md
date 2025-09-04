Sinceides Learning Management System (LMS)

📖 Overview

Sinceides is a comprehensive Learning Management System (LMS) built with Node.js, Express.js, and Firebase Firestore. This platform provides a complete solution for online education with advanced features like adaptive learning, analytics, challenges, and certifications.

Developer: Omar Essayed
Powered by: Ozex

🚀 Key Features

· Multi-role System: Admin, Instructor, Student, HR, and Support roles
· Course Management: Create, manage, and publish courses with lessons
· Adaptive Learning: AI-powered content adjustment based on user performance
· Challenges & Exams: Daily, weekly, and monthly challenges with exams and certifications
· Advanced Analytics: Predictive analytics for student performance and risk identification
· Roadmaps: Structured learning paths with multiple courses
· Support System: Integrated support ticket system with round-robin assignment
· Real-time Leaderboards: For challenges and competitions
· Certificate Generation: Automated certificate issuance with verification
· Redis Caching: Performance optimization with Redis caching
· RESTful API: Comprehensive API with Swagger documentation

🛠 Tech Stack

· Backend: Node.js, Express.js, TypeScript
· Database: Firebase Firestore
· Caching: Redis (Upstash)
· Authentication: JWT, Passport.js
· File Upload: Multer
· Documentation: Swagger/OpenAPI
· Logging: Winston with Morgan
· Validation: Zod
· PDF Generation: PDFKit
· CSV Export: csv-writer

📋 Prerequisites

· Node.js 16+
· Firebase Project with Service Account
· Redis Instance (Upstash recommended)
· npm or yarn

🔧 Installation

1. Clone the repository
   ```bash
   git clone <repository-url>
   cd sinceides-lms
   ```
2. Install dependencies
   ```bash
   npm install
   ```
3. Environment Configuration Create a .env file in the root directory:
   ```env
   PORT=4000
   JWT_SECRET=your_jwt_secret_here
   JWT_ACCESS_EXPIRY=15m
   JWT_REFRESH_EXPIRY=7d
   FIRESTORE_ENABLED=true
   FIRESTORE_PREFIX=prod
   CORS_ORIGIN=*
   
   # Firebase Service Account Path
   # Place your service account JSON in config/ directory
   ```
4. Firebase Setup
   · Create a Firebase project
   · Generate a service account key
   · Place the JSON file at config/sinceidesv2-firebase-adminsdk-fbsvc-22bac469f1.json
   · Enable Firestore in your Firebase project
5. Redis Setup
   · Create a Redis instance (Upstash recommended)
   · Update Redis connection details in the server code

🏃‍♂️ Running the Application

Development Mode

```bash
npm run dev
```

Production Mode

```bash
npm start
```

Database Seeding

```bash
npm run seed
```

📁 Project Structure

```
src/
├── controllers/          # Route controllers
├── middleware/          # Custom middleware
├── models/             # Data models and interfaces
├── repositories/       # Database operations
├── services/           # Business logic
├── types/             # TypeScript definitions
├── utils/             # Utility functions
├── config/            # Configuration files
├── uploads/           # File upload directory
├── data/              # Data exports and snapshots
└── logs/              # Application logs
```

🔐 Authentication & Authorization

Roles and Permissions

· Admin: Full system access
· Instructor: Course and content management
· Student: Course enrollment and learning
· HR: Instructor management and reporting
· Support: Customer support management

API Authentication

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

📊 API Documentation

After starting the server, access the Swagger documentation at:

```
http://localhost:4000/docs
```

🧪 Testing

Run the test suite:

```bash
npm test
```

📈 Performance Optimization

· Redis caching for frequently accessed data
· Pagination for large datasets
· Compression middleware for response size reduction
· Rate limiting to prevent abuse
· Helmet.js for security headers

🔄 Database Operations

Snapshots

Create a database snapshot:

```bash
npm run snapshot
```

Restore from a snapshot:

```bash
npm run restore -- <snapshot-directory>
```

🚨 Error Handling

The application uses a centralized error handling system with:

· Structured error responses
· HTTP status codes
· Detailed error logging
· Validation error formatting

📝 Logging

Logs are stored in the logs/ directory with:

· error.log: All error messages
· combined.log: All log messages

🔒 Security Features

· JWT authentication with refresh tokens
· Role-based access control
· Password complexity enforcement
· File upload restrictions
· Rate limiting
· CORS configuration
· Helmet.js security headers

🎯 Advanced Features

Adaptive Learning

· Content difficulty adjustment based on user performance
· Personalized learning paths
· Learning style detection

Predictive Analytics

· Course completion probability
· At-risk student identification
· Intervention recommendations

Challenge System

· Multiple challenge types (daily, weekly, monthly)
· Real-time leaderboards
· Scoring and ranking system

📋 API Examples

User Registration

```bash
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "Passw0rd!",
    "phoneNumber": "+123456789",
    "role": "student"
  }'
```

User Login

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "Passw0rd!"
  }'
```

Create Course

```bash
curl -X POST http://localhost:4000/api/courses \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Introduction to Programming",
    "description": "Learn programming basics",
    "thumbnailUrl": "https://example.com/thumbnail.jpg",
    "instructorId": "instructor-id",
    "categoryId": "category-id",
    "language": "English",
    "level": "Beginner",
    "tags": ["programming", "beginner"]
  }'
```

🗂 Database Collections

The application uses the following Firestore collections:

· users - User accounts and profiles
· courses - Course information
· lessons - Lesson content
· enrollments - User course enrollments
· categories - Course categories
· support_conversations - Support tickets
· exams - Exam definitions
· exam_attempts - User exam attempts
· certificates - User certificates
· roadmaps - Learning roadmaps
· challenges - Learning challenges
· learning_profiles - User learning preferences
· recommendations - Personalized recommendations

🔧 Configuration Options

Environment Variables

· PORT: Server port (default: 4000)
· JWT_SECRET: Secret for JWT signing
· JWT_ACCESS_EXPIRY: Access token expiry (default: 15m)
· JWT_REFRESH_EXPIRY: Refresh token expiry (default: 7d)
· FIRESTORE_ENABLED: Enable/disable Firestore (default: true)
· FIRESTORE_PREFIX: Firestore collection prefix (default: prod)
· UPLOAD_DIR: File upload directory (default: uploads/)
· DATA_DIR: Data storage directory (default: data/)

Firebase Configuration

Update the Firebase service account path and project details in the server configuration.

📞 Support

For support regarding this application, please contact:

· Developer: Omar Essayed
· Organization: Ozex

📄 License

This project is proprietary software developed by Ozex. All rights reserved.

🔄 Version History

· v1.0.0 - Initial release with core LMS functionality
· v1.1.0 - Added adaptive learning and analytics features
· v1.2.0 - Enhanced challenge system and performance improvements

---

Note: This is a production-ready LMS platform with comprehensive features for online education. Ensure proper configuration of all services before deployment.
