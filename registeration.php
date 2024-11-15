<?php
// Start the session for CSRF token handling
session_start();




// Include the database connection file
include('db-connection.php');

// Generate CSRF token if not already generated
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Initialize variables for error messages
$usernameErr = $emailErr = $passwordErr = "";

// Define the OWASP password policy requirements
$passwordPolicy = [
    'minLength' => 8,
    'uppercase' => '/[A-Z]/',
    'lowercase' => '/[a-z]/',
    'number' => '/[0-9]/',
    'specialChar' => '/[!@#$%^&*(),.?":{}|<>]/',
    'commonPasswords' => ["password", "123456", "12345678", "qwerty", "abc123"] // Example of common passwords
];

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }

    // Get form data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirmPassword'];

    // Validate username
    if (empty($username)) {
        $usernameErr = "Username is required";
    }

    // Validate email
    if (empty($email)) {
        $emailErr = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $emailErr = "Invalid email format";
    }

    // Validate password
    if (empty($password)) {
        $passwordErr = "Password is required";
    } elseif (strlen($password) < $passwordPolicy['minLength']) {
        $passwordErr .= "Password must be at least " . $passwordPolicy['minLength'] . " characters long.<br>";
    } elseif (!preg_match($passwordPolicy['uppercase'], $password)) {
        $passwordErr .= "Password must contain at least one uppercase letter.<br>";
    } elseif (!preg_match($passwordPolicy['lowercase'], $password)) {
        $passwordErr .= "Password must contain at least one lowercase letter.<br>";
    } elseif (!preg_match($passwordPolicy['number'], $password)) {
        $passwordErr .= "Password must contain at least one number.<br>";
    } elseif (!preg_match($passwordPolicy['specialChar'], $password)) {
        $passwordErr .= "Password must contain at least one special character.<br>";
    } elseif (in_array(strtolower($password), $passwordPolicy['commonPasswords'])) {
        $passwordErr .= "Password is too common. Please choose a stronger password.<br>";
    } elseif ($password !== $confirmPassword) {
        $passwordErr .= "Passwords do not match.<br>";
    }

    // If no errors, proceed to insert into the database
    if (empty($usernameErr) && empty($emailErr) && empty($passwordErr)) {
        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Use a prepared statement to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashedPassword);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>alert('Registration Successful!'); window.location.href = 'login.php';</script>";
            exit();
        } else {
            echo "<script>alert('Error: Could not register user. Please try again.');</script>";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Page</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>

<div class="container mt-5">
    <div class="registration-container">
        <h2>Register New User</h2>
        <form id="registrationForm" method="POST" action="">

            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <div class="input-group mb-3">
                <i class="fas fa-user"></i>
                <input type="text" id="username" name="username" placeholder="Username" required value="<?php echo htmlspecialchars($name ?? ''); ?>">
            </div>

            <div class="input-group mb-3">
                <i class="fas fa-envelope"></i>
                <input type="email" id="email" name="email" placeholder="Email" required value="<?php echo htmlspecialchars($email ?? ''); ?>">
            </div>

            <div class="input-group mb-3">
                <i class="fas fa-key"></i>
                <input type="password" id="password" name="password" placeholder="Password" required>
                <i class="fas fa-eye toggle-password" onclick="togglePassword('password')"></i>
            </div>

            <div class="input-group mb-3">
                <i class="fas fa-key"></i>
                <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Confirm Password" required>
                <i class="fas fa-eye toggle-password" onclick="togglePassword('confirmPassword')"></i>
            </div>

            <button type="submit" class="register-button">Register</button>

            <!-- Display errors below the register button -->
            <div class="error-message">
                <?php
                    echo $usernameErr ? "<p>$usernameErr</p>" : '';
                    echo $emailErr ? "<p>$emailErr</p>" : '';
                    echo $passwordErr ? "<p>$passwordErr</p>" : '';
                ?>
            </div>

            <!-- Go Back hyperlink -->
            <div class="go-back">
                <a href="login.php">Go Back to Login</a>
            </div>
        </form>
    </div>
</div>

<script>
    // Toggle password visibility
    function togglePassword(fieldId) {
        const passwordInput = document.getElementById(fieldId);
        const eyeIcon = passwordInput.nextElementSibling;

        if (passwordInput.type === "password") {
            passwordInput.type = "text";
            eyeIcon.classList.remove("fa-eye");
            eyeIcon.classList.add("fa-eye-slash");
        } else {
            passwordInput.type = "password";
            eyeIcon.classList.remove("fa-eye-slash");
            eyeIcon.classList.add("fa-eye");
        }
    }
</script>

</body>
</html>
