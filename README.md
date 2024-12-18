# CourseConnectAPI

A robust API for managing user accounts, courses, enrollments, and role-based authentication in an educational platform. Built with Flask, Google Cloud Datastore, and Auth0.

## Features

- **User Management**:
  - Create, read, update, and delete user accounts.
  - Support for different roles: `student`, `instructor`, and `admin`.
  - Secure authentication and authorization using JSON Web Tokens (JWT) and Auth0.

- **Course Management**:
  - CRUD operations for courses, including assigning instructors.
  - Pagination for listing courses.

- **Enrollment Management**:
  - Add and remove students from courses.
  - Retrieve lists of enrolled students.
  - Role-based restrictions on enrollment actions.

- **Avatar Management**:
  - Upload, retrieve, and delete user avatars stored in Google Cloud Storage.

- **Secure Authorization**:
  - Role-based access control (RBAC) for admin and instructor privileges.
  - JWT verification for secure API access.
