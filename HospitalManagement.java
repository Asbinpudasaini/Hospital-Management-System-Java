
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HospitalManagement {

    // ================= CONFIGURATION =================

    private static final Scanner sc = new Scanner(System.in);
    private static final SecureRandom random = new SecureRandom();

    private static final Path DATA_DIR =
            Paths.get(System.getProperty("user.home"),
                    "HospitalManagementData");

    private static final Path USER_FILE = DATA_DIR.resolve("users.txt");
    private static final Path PATIENT_FILE = DATA_DIR.resolve("patients.txt");
    private static final Path DOCTOR_FILE = DATA_DIR.resolve("doctors.txt");
    private static final Path APPOINTMENT_FILE =
            DATA_DIR.resolve("appointments.txt");
    private static final Path BILL_FILE = DATA_DIR.resolve("bills.txt");

    private static final int ITERATIONS = 120000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;

    private static String loggedInUsername;
    private static String loggedInRole;

    private static final List<Patient> patients = new ArrayList<>();
    private static final List<Doctor> doctors = new ArrayList<>();
    private static final List<Appointment> appointments = new ArrayList<>();
    private static final List<Bill> bills = new ArrayList<>();

    // ================= MAIN =================

    public static void main(String[] args) {

        try {
            initializeStorage();
            setupDefaultUsers();
            loadAllData();

            if (login()) {

                if ("ADMIN".equals(loggedInRole)) {
                    adminMenu();
                } else if ("RECEPTIONIST".equals(loggedInRole)) {
                    receptionistMenu();
                } else {
                    System.out.println("Unknown user role.");
                }
            }

        } catch (Exception e) {
            System.out.println("Application error: " + e.getMessage());
        }

        System.out.println(
                "\nThank you for using Hospital Management System.");
    }

    // ================= STORAGE =================

    private static void initializeStorage() throws IOException {

        Files.createDirectories(DATA_DIR);

        List<Path> files = Arrays.asList(
                USER_FILE,
                PATIENT_FILE,
                DOCTOR_FILE,
                APPOINTMENT_FILE,
                BILL_FILE
        );

        for (Path file : files) {
            if (!Files.exists(file)) {
                Files.createFile(file);
            }
        }
    }

    private static void setupDefaultUsers() throws Exception {

        if (Files.size(USER_FILE) > 0) {
            return;
        }

        String admin = createPasswordRecord("Admin@2026");
        String receptionist =
                createPasswordRecord("Reception@2026");

        List<String> users = Arrays.asList(
                "admin|ADMIN|" + admin,
                "receptionist|RECEPTIONIST|" + receptionist
        );

        writeSafely(USER_FILE, users);

        System.out.println("Default accounts created.");
        System.out.println("Username: admin");
        System.out.println("Username: receptionist");
    }

    // ================= PASSWORD SECURITY =================

    private static String createPasswordRecord(String password)
            throws Exception {

        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        byte[] hash =
                hashPassword(password.toCharArray(), salt);

        return Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

    private static byte[] hashPassword(
            char[] password, byte[] salt) throws Exception {

        PBEKeySpec spec = new PBEKeySpec(
                password, salt, ITERATIONS, HASH_LENGTH * 8);

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256");

            return factory.generateSecret(spec).getEncoded();

        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    private static boolean verifyPassword(
            String password, String storedRecord) throws Exception {

        String[] parts;

        if (storedRecord.contains(":")) {
            parts = storedRecord.split(":", -1);
        } else {
            parts = storedRecord.split("\\|", -1);
        }

        if (parts.length != 2) {
            return false;
        }

        try {
            byte[] salt =
                    Base64.getDecoder().decode(parts[0]);

            byte[] expected =
                    Base64.getDecoder().decode(parts[1]);

            // Current PBKDF2 format
            byte[] actual =
                    hashPassword(password.toCharArray(), salt);

            if (MessageDigest.isEqual(expected, actual)) {
                return true;
            }

            // Legacy PBKDF2 formats
            int[] oldIterations = {100000, 65536, 10000};

            for (int count : oldIterations) {

                PBEKeySpec spec = new PBEKeySpec(
                        password.toCharArray(),
                        salt,
                        count,
                        expected.length * 8
                );

                try {
                    SecretKeyFactory factory =
                            SecretKeyFactory.getInstance(
                                    "PBKDF2WithHmacSHA256");

                    byte[] oldHash =
                            factory.generateSecret(spec).getEncoded();

                    if (MessageDigest.isEqual(expected, oldHash)) {
                        return true;
                    }

                } finally {
                    spec.clearPassword();
                }
            }

            // Legacy SHA-256 formats
            MessageDigest sha =
                    MessageDigest.getInstance("SHA-256");

            byte[] passwordBytes =
                    password.getBytes(StandardCharsets.UTF_8);

            byte[] saltFirst =
                    new byte[salt.length + passwordBytes.length];

            System.arraycopy(
                    salt, 0, saltFirst, 0, salt.length);

            System.arraycopy(
                    passwordBytes, 0,
                    saltFirst, salt.length, passwordBytes.length);

            byte[] hash1 = sha.digest(saltFirst);

            if (MessageDigest.isEqual(expected, hash1)) {
                return true;
            }

            byte[] passwordFirst =
                    new byte[passwordBytes.length + salt.length];

            System.arraycopy(
                    passwordBytes, 0,
                    passwordFirst, 0, passwordBytes.length);

            System.arraycopy(
                    salt, 0,
                    passwordFirst, passwordBytes.length, salt.length);

            byte[] hash2 = sha.digest(passwordFirst);

            if (MessageDigest.isEqual(expected, hash2)) {
                return true;
            }

            // Legacy unsalted SHA-256
            byte[] hash3 = sha.digest(passwordBytes);

            return MessageDigest.isEqual(expected, hash3);

        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // ================= LOGIN =================

    private static boolean login() throws Exception {

        System.out.println("\n========== HOSPITAL LOGIN ==========");

        for (int attempt = 1; attempt <= 3; attempt++) {

            System.out.print("Enter Username: ");
            String username = sc.nextLine().trim();

            System.out.print("Enter Password: ");
            String password = sc.nextLine();

            List<String> lines =
                    Files.readAllLines(
                            USER_FILE, StandardCharsets.UTF_8);

            for (String line : lines) {

                String[] data = line.split("\\|", -1);

                if (data.length != 3 && data.length != 4) {
                    continue;
                }

                String storedRecord;

                if (data.length == 4) {
                    storedRecord = data[2] + "|" + data[3];
                } else {
                    storedRecord = data[2];
                }

                if (data[0].equals(username)
                        && verifyPassword(password, storedRecord)) {

                    loggedInUsername = username;
                    loggedInRole = data[1];

                    // Upgrade legacy password records
                    if (data.length == 4
                            || !storedRecord.contains(":")) {

                        updatePasswordRecord(
                                username, data[1], password);
                    }

                    System.out.println("\nLogin successful!");
                    System.out.println("Welcome, " + username);
                    System.out.println("Role: " + loggedInRole);

                    return true;
                }
            }

            System.out.println("Invalid Username or Password!");
            System.out.println(
                    "Attempts remaining: " + (3 - attempt));
        }

        System.out.println("Maximum login attempts reached.");
        return false;
    }

    private static void updatePasswordRecord(
            String username, String role, String password)
            throws Exception {

        List<String> lines =
                Files.readAllLines(
                        USER_FILE, StandardCharsets.UTF_8);

        List<String> updated = new ArrayList<>();

        String newRecord = createPasswordRecord(password);

        for (String line : lines) {

            String[] data = line.split("\\|", -1);

            if (data.length >= 3 && data[0].equals(username)) {
                updated.add(
                        username + "|" + role + "|" + newRecord);
            } else {
                updated.add(line);
            }
        }

        writeSafely(USER_FILE, updated);
    }

    private static void changePassword() throws Exception {

        System.out.print("Enter current password: ");
        String current = sc.nextLine();

        List<String> lines =
                Files.readAllLines(
                        USER_FILE, StandardCharsets.UTF_8);

        List<String> updated = new ArrayList<>();
        boolean changed = false;

        for (String line : lines) {

            String[] data = line.split("\\|", -1);

            if (data.length < 3) {
                updated.add(line);
                continue;
            }

            if (data[0].equals(loggedInUsername)) {

                String stored;

                if (data.length == 4) {
                    stored = data[2] + "|" + data[3];
                } else {
                    stored = data[2];
                }

                if (!verifyPassword(current, stored)) {
                    System.out.println(
                            "Current password is incorrect.");
                    return;
                }

                System.out.print("Enter new password: ");
                String newPassword = sc.nextLine();

                if (newPassword.length() < 8) {
                    System.out.println(
                            "Password must be at least 8 characters.");
                    return;
                }

                if (newPassword.equals(current)) {
                    System.out.println(
                            "New password must be different.");
                    return;
                }

                updated.add(
                        data[0] + "|" + data[1] + "|"
                                + createPasswordRecord(newPassword));

                changed = true;

            } else {
                updated.add(line);
            }
        }

        if (changed) {
            writeSafely(USER_FILE, updated);
            System.out.println(
                    "Password changed successfully.");
        } else {
            System.out.println("User not found.");
        }
    }

    // ================= SAFE FILE WRITING =================

    private static void writeSafely(
            Path file, List<String> lines) throws IOException {

        Path temp =
                file.resolveSibling(
                        file.getFileName() + ".tmp");

        Files.write(
                temp, lines, StandardCharsets.UTF_8);

        try {
            Files.move(
                    temp,
                    file,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
            );

        } catch (IOException e) {

            Files.move(
                    temp,
                    file,
                    StandardCopyOption.REPLACE_EXISTING
            );
        }
    }

    // ================= DATA LOADING =================

    private static void loadAllData() throws IOException {

        patients.clear();
        doctors.clear();
        appointments.clear();
        bills.clear();

        // Load patients
        for (String line :
                Files.readAllLines(
                        PATIENT_FILE, StandardCharsets.UTF_8)) {

            try {
                String[] d = line.split("\\|", -1);

                if (d.length == 5 || d.length == 6) {

                    patients.add(new Patient(
                            Integer.parseInt(d[0]),
                            decode(d[1]),
                            decode(d[2]),
                            Integer.parseInt(d[3]),
                            decode(d[4]),
                            d.length == 6
                                    ? decode(d[5]) : "ACTIVE"
                    ));
                }

            } catch (Exception e) {
                System.out.println(
                        "Skipped invalid patient record.");
            }
        }

        // Load doctors
        for (String line :
                Files.readAllLines(
                        DOCTOR_FILE, StandardCharsets.UTF_8)) {

            try {
                String[] d = line.split("\\|", -1);

                if (d.length == 4) {

                    doctors.add(new Doctor(
                            Integer.parseInt(d[0]),
                            decode(d[1]),
                            decode(d[2]),
                            decode(d[3])
                    ));
                }

            } catch (Exception e) {
                System.out.println(
                        "Skipped invalid doctor record.");
            }
        }

        // Load appointments
        for (String line :
                Files.readAllLines(
                        APPOINTMENT_FILE, StandardCharsets.UTF_8)) {

            try {
                String[] d = line.split("\\|", -1);

                if (d.length == 5) {

                    appointments.add(new Appointment(
                            Integer.parseInt(d[0]),
                            Integer.parseInt(d[1]),
                            Integer.parseInt(d[2]),
                            LocalDate.parse(d[3]),
                            decode(d[4])
                    ));
                }

            } catch (Exception e) {
                System.out.println(
                        "Skipped invalid appointment record.");
            }
        }

        // Load bills
        for (String line :
                Files.readAllLines(
                        BILL_FILE, StandardCharsets.UTF_8)) {

            try {
                String[] d = line.split("\\|", -1);

                if (d.length == 4) {

                    bills.add(new Bill(
                            Integer.parseInt(d[0]),
                            Integer.parseInt(d[1]),
                            new BigDecimal(d[2]),
                            decode(d[3])
                    ));
                }

            } catch (Exception e) {
                System.out.println(
                        "Skipped invalid bill record.");
            }
        }
    }

    // ================= ENCODING =================

    private static String encode(String value) {

        return Base64.getEncoder().encodeToString(
                value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {

        return new String(
                Base64.getDecoder().decode(value),
                StandardCharsets.UTF_8);
    }

    // ================= SAVE DATA =================

    private static void savePatients() throws IOException {

        List<String> lines = new ArrayList<>();

        for (Patient p : patients) {

            lines.add(
                    p.id + "|"
                            + encode(p.name) + "|"
                            + encode(p.gender) + "|"
                            + p.age + "|"
                            + encode(p.phone) + "|"
                            + encode(p.status)
            );
        }

        writeSafely(PATIENT_FILE, lines);
    }

    private static void saveDoctors() throws IOException {

        List<String> lines = new ArrayList<>();

        for (Doctor d : doctors) {

            lines.add(
                    d.id + "|"
                            + encode(d.name) + "|"
                            + encode(d.specialization) + "|"
                            + encode(d.phone)
            );
        }

        writeSafely(DOCTOR_FILE, lines);
    }

    private static void saveAppointments() throws IOException {

        List<String> lines = new ArrayList<>();

        for (Appointment a : appointments) {

            lines.add(
                    a.id + "|"
                            + a.patientId + "|"
                            + a.doctorId + "|"
                            + a.date + "|"
                            + encode(a.status)
            );
        }

        writeSafely(APPOINTMENT_FILE, lines);
    }

    private static void saveBills() throws IOException {

        List<String> lines = new ArrayList<>();

        for (Bill b : bills) {

            lines.add(
                    b.id + "|"
                            + b.patientId + "|"
                            + b.amount.toPlainString() + "|"
                            + encode(b.status)
            );
        }

        writeSafely(BILL_FILE, lines);
    }

    // ================= ADMIN MENU =================

    private static void adminMenu() {

        while (true) {

            System.out.println(
                    "\n========== ADMIN DASHBOARD ==========");

            System.out.println("1. Register Patient");
            System.out.println("2. View Patients");
            System.out.println("3. Search Patient");
            System.out.println("4. Update Patient");
            System.out.println("5. Delete Patient");
            System.out.println("6. Discharge Patient");
            System.out.println("7. Add Doctor");
            System.out.println("8. View Doctors");
            System.out.println("9. Update Doctor");
            System.out.println("10. Delete Doctor");
            System.out.println("11. Book Appointment");
            System.out.println("12. View Appointments");
            System.out.println("13. Cancel Appointment");
            System.out.println("14. Create Medical Bill");
            System.out.println("15. View Bills");
            System.out.println("16. Mark Bill as Paid");
            System.out.println("17. Change Password");
            System.out.println("0. Logout");

            int choice = readInt("Choose option: ");

            try {
                switch (choice) {

                    case 1 -> registerPatient();
                    case 2 -> viewPatients();
                    case 3 -> searchPatient();
                    case 4 -> updatePatient();
                    case 5 -> deletePatient();
                    case 6 -> dischargePatient();
                    case 7 -> addDoctor();
                    case 8 -> viewDoctors();
                    case 9 -> updateDoctor();
                    case 10 -> deleteDoctor();
                    case 11 -> bookAppointment();
                    case 12 -> viewAppointments();
                    case 13 -> cancelAppointment();
                    case 14 -> createBill();
                    case 15 -> viewBills();
                    case 16 -> markBillPaid();
                    case 17 -> changePassword();

                    case 0 -> {
                        return;
                    }

                    default ->
                            System.out.println("Invalid option.");
                }

            } catch (Exception e) {
                System.out.println(
                        "Operation failed: " + e.getMessage());
            }
        }
    }

    // ================= RECEPTIONIST MENU =================

    private static void receptionistMenu() {

        while (true) {

            System.out.println(
                    "\n====== RECEPTIONIST DASHBOARD ======");

            System.out.println("1. Register Patient");
            System.out.println("2. View Patients");
            System.out.println("3. Search Patient");
            System.out.println("4. Book Appointment");
            System.out.println("5. View Appointments");
            System.out.println("6. Create Medical Bill");
            System.out.println("7. View Bills");
            System.out.println("8. Mark Bill as Paid");
            System.out.println("9. Change Password");
            System.out.println("0. Logout");

            int choice = readInt("Choose option: ");

            try {
                switch (choice) {

                    case 1 -> registerPatient();
                    case 2 -> viewPatients();
                    case 3 -> searchPatient();
                    case 4 -> bookAppointment();
                    case 5 -> viewAppointments();
                    case 6 -> createBill();
                    case 7 -> viewBills();
                    case 8 -> markBillPaid();
                    case 9 -> changePassword();

                    case 0 -> {
                        return;
                    }

                    default ->
                            System.out.println("Invalid option.");
                }

            } catch (Exception e) {
                System.out.println(
                        "Operation failed: " + e.getMessage());
            }
        }
    }

    // ================= PATIENT MANAGEMENT =================

    private static void registerPatient() throws IOException {

        System.out.println("\n--- REGISTER PATIENT ---");

        int id = nextPatientId();

        String name = readText("Patient name: ");
        String gender = readGender("Gender (Male/Female/Other): ");
        int age = readAge("Age: ");
        String phone = readPhone("Phone: ");

        patients.add(new Patient(
                id, name, gender, age, phone, "ACTIVE"));

        savePatients();

        System.out.println(
                "Patient registered successfully.");
        System.out.println("Patient ID: " + id);
    }

    private static int nextPatientId() {

        return patients.stream()
                .mapToInt(p -> p.id)
                .max()
                .orElse(1000) + 1;
    }

    private static void viewPatients() {

        System.out.println("\n========== PATIENT LIST ==========");

        if (patients.isEmpty()) {
            System.out.println("No patients found.");
            return;
        }

        for (Patient p : patients) {
            System.out.println(p);
        }
    }

    private static void searchPatient() {

        int id = readInt("Enter patient ID: ");
        Patient p = findPatient(id);

        if (p == null) {
            System.out.println("Patient not found.");
        } else {
            System.out.println(p);
        }
    }

    private static void updatePatient() throws IOException {

        int id = readInt("Enter patient ID: ");
        Patient p = findPatient(id);

        if (p == null) {
            System.out.println("Patient not found.");
            return;
        }

        // Validate all input before changing patient data
        String name = readText("New name: ");
        String gender =
                readGender("New gender (Male/Female/Other): ");
        int age = readAge("New age: ");
        String phone = readPhone("New phone: ");

        p.name = name;
        p.gender = gender;
        p.age = age;
        p.phone = phone;

        savePatients();

        System.out.println(
                "Patient updated successfully.");
    }

    private static void deletePatient() throws IOException {

        int id = readInt("Enter patient ID: ");
        Patient p = findPatient(id);

        if (p == null) {
            System.out.println("Patient not found.");
            return;
        }

        boolean hasHistory =
                appointments.stream()
                        .anyMatch(a -> a.patientId == id)
                || bills.stream()
                        .anyMatch(b -> b.patientId == id);

        if (hasHistory) {
            System.out.println(
                    "Cannot delete patient with medical history.");
            return;
        }

        patients.remove(p);
        savePatients();

        System.out.println(
                "Patient deleted successfully.");
    }

    private static void dischargePatient() throws IOException {

        int id = readInt("Enter patient ID: ");
        Patient p = findPatient(id);

        if (p == null) {
            System.out.println("Patient not found.");
            return;
        }

        if ("DISCHARGED".equals(p.status)) {
            System.out.println(
                    "Patient is already discharged.");
            return;
        }

        p.status = "DISCHARGED";
        savePatients();

        System.out.println(
                "Patient discharged successfully.");
    }

    private static Patient findPatient(int id) {

        return patients.stream()
                .filter(p -> p.id == id)
                .findFirst()
                .orElse(null);
    }

    // ================= DOCTOR MANAGEMENT =================

    private static void addDoctor() throws IOException {

        int id = doctors.stream()
                .mapToInt(d -> d.id)
                .max()
                .orElse(200) + 1;

        System.out.println("\n--- ADD DOCTOR ---");

        String name = readText("Doctor name: ");
        String specialization =
                readText("Specialization: ");
        String phone = readPhone("Phone: ");

        doctors.add(new Doctor(
                id, name, specialization, phone));

        saveDoctors();

        System.out.println("Doctor added successfully.");
        System.out.println("Doctor ID: " + id);
    }

    private static void viewDoctors() {

        System.out.println("\n========== DOCTOR LIST ==========");

        if (doctors.isEmpty()) {
            System.out.println("No doctors found.");
            return;
        }

        for (Doctor d : doctors) {
            System.out.println(d);
        }
    }

    private static void updateDoctor() throws IOException {

        int id = readInt("Enter doctor ID: ");
        Doctor d = findDoctor(id);

        if (d == null) {
            System.out.println("Doctor not found.");
            return;
        }

        // Validate before changing doctor data
        String name = readText("New doctor name: ");
        String specialization =
                readText("New specialization: ");
        String phone = readPhone("New phone: ");

        d.name = name;
        d.specialization = specialization;
        d.phone = phone;

        saveDoctors();

        System.out.println(
                "Doctor updated successfully.");
    }

    private static void deleteDoctor() throws IOException {

        int id = readInt("Enter doctor ID: ");
        Doctor d = findDoctor(id);

        if (d == null) {
            System.out.println("Doctor not found.");
            return;
        }

        boolean hasAppointment =
                appointments.stream()
                        .anyMatch(a -> a.doctorId == id);

        if (hasAppointment) {
            System.out.println(
                    "Cannot delete doctor with appointment history.");
            return;
        }

        doctors.remove(d);
        saveDoctors();

        System.out.println(
                "Doctor deleted successfully.");
    }

    private static Doctor findDoctor(int id) {

        return doctors.stream()
                .filter(d -> d.id == id)
                .findFirst()
                .orElse(null);
    }

    // ================= APPOINTMENTS =================

    private static void bookAppointment() throws IOException {

        System.out.println("\n--- BOOK APPOINTMENT ---");

        int patientId = readInt("Patient ID: ");
        Patient patient = findPatient(patientId);

        if (patient == null
                || !"ACTIVE".equals(patient.status)) {

            System.out.println(
                    "Active patient not found.");
            return;
        }

        int doctorId = readInt("Doctor ID: ");

        if (findDoctor(doctorId) == null) {
            System.out.println("Doctor not found.");
            return;
        }

        LocalDate date;

        try {
            date = LocalDate.parse(
                    readText(
                            "Appointment date (YYYY-MM-DD): "));

        } catch (DateTimeParseException e) {
            System.out.println(
                    "Invalid date. Use YYYY-MM-DD.");
            return;
        }

        if (date.isBefore(LocalDate.now())) {
            System.out.println(
                    "Past dates are not allowed.");
            return;
        }

        boolean occupied = appointments.stream().anyMatch(a ->
                a.doctorId == doctorId
                        && a.date.equals(date)
                        && "SCHEDULED".equals(a.status));

        if (occupied) {
            System.out.println(
                    "Doctor already has an appointment on this date.");
            return;
        }

        int id = appointments.stream()
                .mapToInt(a -> a.id)
                .max()
                .orElse(1000) + 1;

        appointments.add(new Appointment(
                id, patientId, doctorId, date, "SCHEDULED"));

        saveAppointments();

        System.out.println(
                "Appointment booked successfully.");
        System.out.println("Appointment ID: " + id);
    }

    private static void viewAppointments() {

        System.out.println(
                "\n========== APPOINTMENTS ==========");

        if (appointments.isEmpty()) {
            System.out.println(
                    "No appointments found.");
            return;
        }

        for (Appointment a : appointments) {
            System.out.println(a);
        }
    }

    private static void cancelAppointment()
            throws IOException {

        int id = readInt("Appointment ID: ");

        for (Appointment a : appointments) {

            if (a.id == id
                    && "SCHEDULED".equals(a.status)) {

                a.status = "CANCELLED";
                saveAppointments();

                System.out.println(
                        "Appointment cancelled successfully.");
                return;
            }
        }

        System.out.println(
                "Scheduled appointment not found.");
    }

    // ================= BILLING =================

    private static void createBill() throws IOException {

        System.out.println(
                "\n--- CREATE MEDICAL BILL ---");

        int patientId = readInt("Patient ID: ");

        if (findPatient(patientId) == null) {
            System.out.println("Patient not found.");
            return;
        }

        BigDecimal amount =
                readAmount("Bill amount: ");

        int id = bills.stream()
                .mapToInt(b -> b.id)
                .max()
                .orElse(3000) + 1;

        bills.add(new Bill(
                id, patientId, amount, "UNPAID"));

        saveBills();

        System.out.println("Bill created successfully.");
        System.out.println("Bill ID: " + id);
    }

    private static void viewBills() {

        System.out.println(
                "\n========== MEDICAL BILLS ==========");

        if (bills.isEmpty()) {
            System.out.println("No bills found.");
            return;
        }

        for (Bill b : bills) {
            System.out.println(b);
        }
    }

    private static void markBillPaid() throws IOException {

        int id = readInt("Enter bill ID: ");

        for (Bill b : bills) {

            if (b.id == id) {

                if ("PAID".equals(b.status)) {
                    System.out.println(
                            "Bill is already paid.");
                    return;
                }

                b.status = "PAID";
                saveBills();

                System.out.println(
                        "Bill marked as paid.");
                return;
            }
        }

        System.out.println("Bill not found.");
    }

    // ================= INPUT HELPERS =================

    private static int readInt(String message) {

        while (true) {

            System.out.print(message);

            try {
                return Integer.parseInt(
                        sc.nextLine().trim());

            } catch (NumberFormatException e) {
                System.out.println(
                        "Please enter a valid number.");
            }
        }
    }

    private static String readText(String message) {

        while (true) {

            System.out.print(message);
            String value = sc.nextLine().trim();

            if (!value.isEmpty()
                    && !value.contains("|")) {

                return value;
            }

            System.out.println(
                    "Input cannot be empty or contain |.");
        }
    }

    private static int readAge(String message) {

        while (true) {

            int age = readInt(message);

            if (age >= 1 && age <= 130) {
                return age;
            }

            System.out.println(
                    "Age must be between 1 and 130.");
        }
    }

    private static String readGender(String message) {

        while (true) {

            String gender = readText(message);

            if (gender.equalsIgnoreCase("Male")) {
                return "Male";
            }

            if (gender.equalsIgnoreCase("Female")) {
                return "Female";
            }

            if (gender.equalsIgnoreCase("Other")) {
                return "Other";
            }

            System.out.println(
                    "Enter Male, Female, or Other.");
        }
    }

    private static String readPhone(String message) {

        while (true) {

            String phone = readText(message);

            if (phone.matches("\\+?[0-9]{10,15}")) {
                return phone;
            }

            System.out.println(
                    "Enter a valid phone number (10-15 digits).");
        }
    }

    private static BigDecimal readAmount(String message) {

        while (true) {

            System.out.print(message);
            String input = sc.nextLine().trim();

            try {
                if (!input.matches(
                        "[0-9]{1,10}(\\.[0-9]{1,2})?")) {

                    throw new NumberFormatException();
                }

                BigDecimal amount = new BigDecimal(input);

                if (amount.compareTo(BigDecimal.ZERO) > 0) {
                    return amount;
                }

            } catch (NumberFormatException e) {
                // Show validation message below
            }

            System.out.println(
                    "Enter a positive amount with maximum 2 decimal places.");
        }
    }

    // ================= MODEL: PATIENT =================

    static class Patient {

        int id;
        String name;
        String gender;
        int age;
        String phone;
        String status;

        Patient(int id, String name, String gender,
                int age, String phone, String status) {

            this.id = id;
            this.name = name;
            this.gender = gender;
            this.age = age;
            this.phone = phone;
            this.status = status;
        }

        @Override
        public String toString() {

            return "\nPatient ID: " + id
                    + "\nName: " + name
                    + "\nGender: " + gender
                    + "\nAge: " + age
                    + "\nPhone: " + phone
                    + "\nStatus: " + status
                    + "\n--------------------------";
        }
    }

    // ================= MODEL: DOCTOR =================

    static class Doctor {

        int id;
        String name;
        String specialization;
        String phone;

        Doctor(int id, String name,
                String specialization, String phone) {

            this.id = id;
            this.name = name;
            this.specialization = specialization;
            this.phone = phone;
        }

        @Override
        public String toString() {

            return "\nDoctor ID: " + id
                    + "\nName: " + name
                    + "\nSpecialization: " + specialization
                    + "\nPhone: " + phone
                    + "\n--------------------------";
        }
    }

    // ================= MODEL: APPOINTMENT =================

    static class Appointment {

        int id;
        int patientId;
        int doctorId;
        LocalDate date;
        String status;

        Appointment(int id, int patientId, int doctorId,
                LocalDate date, String status) {

            this.id = id;
            this.patientId = patientId;
            this.doctorId = doctorId;
            this.date = date;
            this.status = status;
        }

        @Override
        public String toString() {

            return "\nAppointment ID: " + id
                    + "\nPatient ID: " + patientId
                    + "\nDoctor ID: " + doctorId
                    + "\nDate: " + date
                    + "\nStatus: " + status
                    + "\n--------------------------";
        }
    }

    // ================= MODEL: BILL =================

    static class Bill {

        int id;
        int patientId;
        BigDecimal amount;
        String status;

        Bill(int id, int patientId,
                BigDecimal amount, String status) {

            this.id = id;
            this.patientId = patientId;
            this.amount = amount;
            this.status = status;
        }

        @Override
        public String toString() {

            return "\nBill ID: " + id
                    + "\nPatient ID: " + patientId
                    + "\nAmount: " + amount
                    + "\nStatus: " + status
                    + "\n--------------------------";
        }
    }
}
