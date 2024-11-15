<?php
// Start the session
session_start();

// Include the database connection file
include('db-connection.php');

// Initialize error variables
$emailErr = $passwordErr = "";

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the form data
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Validate input (basic checks)
    if (empty($email)) {
        $emailErr = "Email is required.";
    }
    if (empty($password)) {
        $passwordErr = "Password is required.";
    }

    // If there are no errors, proceed to check the database
    if (empty($emailErr) && empty($passwordErr)) {
        // SQL query to fetch the user from the database by email
        $sql = "SELECT id, name, email, password FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);  // Prepare the query
        $stmt->bind_param("s", $email); // Bind the email parameter
        $stmt->execute();  // Execute the query

        $result = $stmt->get_result();
        
        // Check if user exists
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();

            // Verify the password using password_verify() function
            if (password_verify($password, $row['password'])) {
                // Password is correct, start a session and set session variables
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['name'] = $row['name'];
                $_SESSION['email'] = $row['email'];
                
                // Redirect to a user dashboard or home page
                header("Location: dashboard.php"); // Change 'dashboard.php' to your desired location
                exit();
            } else {
                $passwordErr = "Invalid password.";
            }
        } else {
            $emailErr = "No user found with that email.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>

<body>
<!-- Navbar -->
<nav class="navbar navbar-expand-lg navbar-light bg-light fixed-top">
    <a class="navbar-brand" href="#">
        <img src="/WEB_DEVELOPMENT_PROJECT/image/ktmlogo.png" alt="Brand Logo" class="navbar-logo">
    </a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
            <li class="nav-item">
                <a class="nav-link" href="#">Home</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#">About</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#">Contact</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#">Help</a>
            </li>
        </ul>
    </div>
</nav>

<!-- Login Form -->
<div class="login-container">
    <h2>Login</h2>
    <form method="POST" action="">
        <div class="input-group">
            <i class="fas fa-user"></i>
            <input type="email" id="email" name="email" placeholder="Email" required>
        </div>
        <div class="error"><?php echo $emailErr; ?></div>

        <div class="input-group">
            <i class="fas fa-key"></i>
            <input type="password" id="password" name="password" placeholder="Password" required>
            <i class="fas fa-eye toggle-password" onclick="togglePassword()"></i>
        </div>
        <div class="error"><?php echo $passwordErr; ?></div>

        <button type="submit" class="login-button">Login</button>

        <div class="links">
            <a href="/WEB_DEVELOPMENT_PROJECT/Registeration.php">Sign up now</a>
            <span>|</span>
            <a href="#" class="forgot-password">Forget password / Activate account</a>
        </div>
    </form>
</div>

<script>
    // Toggle password visibility
    function togglePassword() {
        const passwordInput = document.getElementById("password");
        const eyeIcon = document.querySelector(".toggle-password");

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
