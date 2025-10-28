<!DOCTYPE html>
<html lang="en">
  <head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Update User Profile
	</title>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  </head>
  <body>
	<div class="registration-container">
	  <div align="center" class="flex">
		<img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" id="inh1m">
	  </div>
	  <div class="header">
		<i class="fas fa-user-plus">
		</i> Update User Profile
	  </div>
	  <!-- Error Message Block -->
	  [#if errorMessage?has_content]
	  <div role="alert" align="center" class="alert alert-danger mt-3 error">
		<p>${errorMessage} 
		</p>
	  </div>
	  [/#if]
	  <div class="content">
		<p class="text-center">Search user by username
		</p>
		<form method="post" enctype="application/x-www-form-urlencoded" id="searchUserForm">
		  <div class="form-group">
			<label class="form-label">Username: <span class="required">*</span></label>
			<input type="text" id="uid" name="uid" pattern="[A-Za-z]+" title="Name should contain only alphabets" required="" placeholder="Choose a username" class="form-control">
		  </div>
		  <input type="hidden" id="formType" name="formType" value="searchUserForm">
		  <div class="buttons">
			<button type="submit" class="btn btn-primary">Search</button>
		  </div>
		</form>
	  </div>
	</div>
  </body>
  <style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f8f9fa;
	  display: flex;
	  justify-content: center;
	  align-items: center;
	  height: 100vh;
	  margin: 0;
	}
	.flex{
	  padding: 10px;
	  margin-top: auto;
	}
	.registration-container {
	  width: 100%;
	  max-width: 600px;
	  background: white;
	  border-radius: 5px;
	  border: #080808;
	  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
	  overflow: hidden;
	}
	.header {
	  background: #28a745;
	  padding: 15px;
	  color: white;
	  font-size: 20px;
	  font-weight: bold;
	  display: flex;
	  align-items: center;
	}
	.header i {
	  margin-right: 10px;
	}
	.content {
	  padding: 20px;
	}
	.form-group {
	  margin-bottom: 15px;
	}
	.form-label {
	  font-weight: bold;
	  display: block;
	  margin-bottom: 5px;
	}
	.form-control {
	  width: 95%;
	  padding: 10px;
	  font-size: 14px;
	  border: 1px solid #ced4da;
	  border-radius: 5px;
	}
	.required {
	  color: red;
	}
	.error-message {
	  color: red;
	  font-size: 13px;
	  margin-top: 5px;
	}
	.error{
	  font-weight: bold;
	  color: red;
	}
	.buttons {
	  display: flex;
	  gap: 10px;
	}
	.btn {
	  padding: 10px 15px;
	  font-size: 16px;
	  border: none;
	  border-radius: 5px;
	  cursor: pointer;
	}
	.btn-primary {
	  background-color: #007bff;
	  color: white;
	}
	.btn-primary:hover {
	  background-color: #0056b3;
	}
	.btn-secondary {
	  background-color: #6c757d;
	  color: white;
	}
	.btn-secondary:hover {
	  background-color: #5a6268;
	}
	.login-link {
	  text-align: center;
	  margin-top: 10px;
	}
	.login-link a {
	  color: #007bff;
	  text-decoration: none;
	  font-weight: bold;
	}
	.login-link a:hover {
	  text-decoration: underline;
	}
  </style>
  <script>
	function validateForm(event) {
	  //let password = document.getElementById("userPassword").value;
	  //let confirmPassword = document.getElementById("confirmPassword").value;
	  //let errorMessage = document.getElementById("error-message");
	  //if (password !== confirmPassword) {
	  //errorMessage.innerText = "Passwords do not match!";
	  //return false;
	  //}
	  //errorMessage.innerText = "";
	  //return true;
	}
  </script>
</html>