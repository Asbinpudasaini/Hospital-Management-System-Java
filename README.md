# Hospital Management System

## Project Overview

A console-based Hospital Management System developed using Java. This application allows administrators and receptionists to manage patients, doctors, appointments, and medical bills.

## Features

### 1. Login System
- Admin and Receptionist login
- Password hashing using PBKDF2WithHmacSHA256
- Maximum 3 login attempts
- Password change functionality

### 2. Patient Management
- Register patients
- View, search, update, and delete patients
- Discharge patients

### 3. Doctor Management
- Add, view, update, and delete doctors

### 4. Appointment Management
- Book and view appointments
- Cancel appointments
- Validate patient and doctor IDs
- Prevent duplicate appointments
- Prevent appointments for discharged patients

### 5. Medical Billing
- Create medical bills
- View bills
- Mark bills as paid
- Support decimal billing amounts

### 6. Data Storage
- File-based data persistence
- UTF-8 file handling
- Data remains available after restarting the application

## Technologies Used
- Java
- Object-Oriented Programming (OOP)
- ArrayList
- File Handling (Java NIO)
- Exception Handling
- Scanner
- PBKDF2WithHmacSHA256
- SecureRandom
- BigDecimal
- LocalDate

## Data Files
- users.txt
- patients.txt
- doctors.txt
- appointments.txt
- bills.txt

## How to Run
1. Open the project in Eclipse IDE.
2. Open `HospitalManagement.java`.
3. Run the Java application.
4. Log in using your configured account.
5. Select options from the menu.

## Developer
Asbin Pudasaini

## Project Type
Java Console-Based Application
