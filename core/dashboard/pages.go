package dashboard

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"goProxy/core/domains"
	"net/http"
)

func PageLogin(writer http.ResponseWriter, request *http.Request) {
	if AdminUser == "" {
		fmt.Fprintf(writer,
			`
			<html>

			<head>
				<style>
				body {
					background-color: #f5f5f5;
					font-family: Arial, sans-serif;
				}
				
				.center {
					display: flex;
					align-items: center;
					justify-content: center;
					height: 100vh;
				}
				
				.box {
					background-color: white;
					border: 1px solid #ddd;
					border-radius: 4px;
					padding: 20px;
					width: 500px;
				}
				
				img {
					display: block;
					margin: 0 auto;
					max-width: 100%%;
				}
				
				input[type="text"] {
					width: 100%%;
					padding: 12px 20px;
					margin: 8px 0;
					box-sizing: border-box;
					border: 2px solid #ccc;
					border-radius: 4px;
				}

				input[type="password"] {
					width: 100%%;
					padding: 12px 20px;
					margin: 8px 0;
					box-sizing: border-box;
					border: 2px solid #ccc;
					border-radius: 4px;
				}
				
				button {
					width: 100%%;
					background-color: #4caf50;
					color: white;
					padding: 14px 20px;
					margin: 8px 0;
					border: none;
					border-radius: 4px;
					cursor: pointer;
				}
				
				button:hover {
					background-color: #45a049;
				}
				/* Add styles for the animation */
				
				.box {
					background-color: white;
					border: 1px solid #ddd;
					border-radius: 4px;
					padding: 20px;
					width: 500px;
					/* Add a transition effect for the height */
					transition: height 0.1s;
					position: block;
				}
				/* Add a transition effect for the opacity */
				
				.box * {
					transition: opacity 0.1s;
				}
				/* Add a success message and style it */
				
				.success {
					background-color: #dff0d8;
					border: 1px solid #d6e9c6;
					border-radius: 4px;
					color: #3c763d;
					padding: 20px;
				}

				.failure {
					background-color: #f0d8d8;
					border: 1px solid #e9c6c6;
					border-radius: 4px;
					color: #763c3c;
					padding: 20px;
				}
				/* Add styles for the collapsible help text */
				
				.collapsible {
					background-color: #f5f5f5;
					color: #444;
					cursor: pointer;
					padding: 18px;
					width: 100%%;
					border: none;
					text-align: left;
					outline: none;
					font-size: 15px;
				}
				
				.collapsible:after {
					content: '\002B';
					color: #777;
					font-weight: bold;
					float: right;
					margin-left: 5px;
				}
				
				.collapsible.active:after {
					content: "\2212";
				}
				
				.collapsible:hover {
					background-color: #e5e5e5;
				}
				
				.collapsible-content {
					padding: 0 18px;
					max-height: 0;
					overflow: hidden;
					transition: max-height 0.2s ease-out;
					background-color: #f5f5f5;
				}
				</style>
			</head>

			<body>
				<div class="center" id="center">
					<div class="box" id="box">
						<h1>balooProxy Dashboard | Register</h1>
						<form onsubmit="return onClick(event)">
							<input id="username" type="text" placeholder="Username" required>
							<input id="password" type="password" placeholder="Password" required>
							<button type="submit">Register</button>
						</form>
						<div class="success" id="successMessage" style="display: none;">Success! Redirecting ...</div>
						<div class="failure" id="failMessage" style="display: none;">Failed! The password must be at least 20 characters long.</div>
						<button class="collapsible">Why do i need to do this?</button>
						<div class="collapsible-content">
							<p> The dashboard will allow you to manage your proxy easily, however you first need to create an admin account </p>
						</div>
					</div>
				</div>
			</body>
			<script>
			function onClick(event) {
				// Prevent the form from being submitted
				event.preventDefault();
				
				var username = document.getElementById('username').value;
				var password = document.getElementById('password').value;

				if(password.length > 20){
					var response = fetch('/_bProxy/`+domains.Config.Proxy.AdminSecret+`/create', {
						method: 'POST',
						mode: 'cors',
						cache: 'no-cache',
						credentials: 'same-origin',
						headers: {
							'Content-Type': 'application/json'
						},
						redirect: 'follow',
						body: JSON.stringify({"username": username, "password": password})
					});
					response.then(resp => {
						resp.text().then(text => {
							if(text == "ok"){
								var failMessage = document.getElementById('failMessage');
								failMessage.style.display = 'none';
								var successMessage = document.getElementById("successMessage");
								successMessage.innerHTML = "Success! Redirecting ..."
								successMessage.style.display = "block";
								location.reload();
							} else {
								var successMessage = document.getElementById("successMessage");
								successMessage.style.display = "none";
								var failMessage = document.getElementById('failMessage');
								failMessage.innerHTML = text
								failMessage.style.display = 'block';
							}
						}).catch(err => {
							var successMessage = document.getElementById("successMessage");
							successMessage.style.display = "none";
							var failMessage = document.getElementById('failMessage');
							failMessage.innerHTML = err
							failMessage.style.display = 'block';
						})
					}).catch(err => {
						var successMessage = document.getElementById("successMessage");
						successMessage.style.display = "none";
						var failMessage = document.getElementById('failMessage');
						failMessage.innerHTML = err
						failMessage.style.display = 'block';
					})
				} else {
					var successMessage = document.getElementById("successMessage");
					successMessage.style.display = "none";
					var failMessage = document.getElementById('failMessage');
					failMessage.innerHTML = "Failed! The password must be at least 20 characters long."
					failMessage.style.display = 'block';
				}
			}
			var coll = document.getElementsByClassName("collapsible");
			var i;
			for(i = 0; i < coll.length; i++) {
				coll[i].addEventListener("click", function() {
					this.classList.toggle("active");
					var content = this.nextElementSibling;
					if(content.style.maxHeight) {
						content.style.maxHeight = null;
					} else {
						content.style.maxHeight = content.scrollHeight + "px";
					}
				});
			}
			</script>

			</html>
			`)
	} else {
		if request.Method == "POST" {
			var adminData AdminData
			err := json.NewDecoder(request.Body).Decode(&adminData)
			if err != nil {
				fmt.Fprintf(writer, "Failed! Invalid request.")
				return
			}
			if adminData.Username == AdminUser && fmt.Sprint(sha256.Sum256([]byte(adminData.Password))) == AdminPassword {
				fmt.Fprintf(writer, "!ok %x", sha256.Sum256([]byte(AdminPassword)))
				return
			} else {
				fmt.Fprintf(writer, "Failed! Invalid username or password")
				return
			}
		} else {
			fmt.Fprintf(writer,
				`
				<html>

				<head>
					<style>
					body {
						background-color: #f5f5f5;
						font-family: Arial, sans-serif;
					}
					
					.center {
						display: flex;
						align-items: center;
						justify-content: center;
						height: 100vh;
					}
					
					.box {
						background-color: white;
						border: 1px solid #ddd;
						border-radius: 4px;
						padding: 20px;
						width: 500px;
					}
					
					img {
						display: block;
						margin: 0 auto;
						max-width: 100%%;
					}
					
					input[type='text'] {
						width: 100%%;
						padding: 12px 20px;
						margin: 8px 0;
						box-sizing: border-box;
						border: 2px solid #ccc;
						border-radius: 4px;
					}
				
					input[type='password'] {
						width: 100%%;
						padding: 12px 20px;
						margin: 8px 0;
						box-sizing: border-box;
						border: 2px solid #ccc;
						border-radius: 4px;
					}
					
					button {
						width: 100%%;
						background-color: #4caf50;
						color: white;
						padding: 14px 20px;
						margin: 8px 0;
						border: none;
						border-radius: 4px;
						cursor: pointer;
					}
					
					button:hover {
						background-color: #45a049;
					}
					/* Add styles for the animation */
					
					.box {
						background-color: white;
						border: 1px solid #ddd;
						border-radius: 4px;
						padding: 20px;
						width: 500px;
						/* Add a transition effect for the height */
						transition: height 0.1s;
						position: block;
					}
					/* Add a transition effect for the opacity */
					
					.box * {
						transition: opacity 0.1s;
					}
					/* Add a success message and style it */
					
					.success {
						background-color: #dff0d8;
						border: 1px solid #d6e9c6;
						border-radius: 4px;
						color: #3c763d;
						padding: 20px;
					}
				
					.failure {
						background-color: #f0d8d8;
						border: 1px solid #e9c6c6;
						border-radius: 4px;
						color: #763c3c;
						padding: 20px;
					}
					/* Add styles for the collapsible help text */
					
					.collapsible {
						background-color: #f5f5f5;
						color: #444;
						cursor: pointer;
						padding: 18px;
						width: 100%%;
						border: none;
						text-align: left;
						outline: none;
						font-size: 15px;
					}
					
					.collapsible:after {
						content: '\002B';
						color: #777;
						font-weight: bold;
						float: right;
						margin-left: 5px;
					}
					
					.collapsible.active:after {
						content: '\2212';
					}
					
					.collapsible:hover {
						background-color: #e5e5e5;
					}
					
					.collapsible-content {
						padding: 0 18px;
						max-height: 0;
						overflow: hidden;
						transition: max-height 0.2s ease-out;
						background-color: #f5f5f5;
					}
					</style>
				</head>
				
				<body>
					<div class='center' id='center'>
						<div class='box' id='box'>
							<h1>balooProxy Dashboard | Login</h1>
							<form onsubmit='return onClick(event)'>
								<input id='username' type='text' placeholder='Username' required>
								<input id='password' type='password' placeholder='Password' required>
								<button type='submit'>Login</button>
							</form>
							<div class='success' id='successMessage' style='display: none;'>Success! Redirecting ...</div>
							<div class='failure' id='failMessage' style='display: none;'>Failed! Wrong username or password.</div>
							<button class='collapsible'>Forgor password?</button>
							<div class='collapsible-content'>
								<p> You can delete/modify 'proxyData.db' in order to reset/change your password and username. </p>
							</div>
						</div>
					</div>
				</body>
				<script>
				function onClick(event) {
					// Prevent the form from being submitted
					event.preventDefault();
					
					var username = document.getElementById('username').value;
					var password = document.getElementById('password').value;
				
					var response = fetch('/_bProxy/`+domains.Config.Proxy.AdminSecret+`/login', {
						method: 'POST',
						mode: 'cors',
						cache: 'no-cache',
						credentials: 'same-origin',
						headers: {
							'Content-Type': 'application/json'
						},
						redirect: 'follow',
						body: JSON.stringify({'username': username, 'password': password})
					});
					response.then(resp => {
						resp.text().then(text => {
							if(text.includes('!ok ')){
								var failMessage = document.getElementById('failMessage');
								failMessage.style.display = 'none';
								document.cookie = 'auth_bProxy_v='+text.split(" ")[1]+'; SameSite=None; path=/; Secure';
								var successMessage = document.getElementById('successMessage');
								successMessage.innerHTML = 'Success! Redirecting ...'
								successMessage.style.display = 'block';
								location.href = "dash"
							} else {
								var successMessage = document.getElementById('successMessage');
								successMessage.style.display = 'none';
								var failMessage = document.getElementById('failMessage');
								failMessage.innerHTML = text
								failMessage.style.display = 'block';
							}
						}).catch(err => {
							var successMessage = document.getElementById('successMessage');
							successMessage.style.display = 'none';
							var failMessage = document.getElementById('failMessage');
							failMessage.innerHTML = err
							failMessage.style.display = 'block';
						})
					}).catch(err => {
						var successMessage = document.getElementById('successMessage');
						successMessage.style.display = 'none';
						var failMessage = document.getElementById('failMessage');
						failMessage.innerHTML = err
						failMessage.style.display = 'block';
					})
				}
				var coll = document.getElementsByClassName('collapsible');
				var i;
				for(i = 0; i < coll.length; i++) {
					coll[i].addEventListener('click', function() {
						this.classList.toggle('active');
						var content = this.nextElementSibling;
						if(content.style.maxHeight) {
							content.style.maxHeight = null;
						} else {
							content.style.maxHeight = content.scrollHeight + 'px';
						}
					});
				}
				</script>
				
				</html>
				`)
			return
		}
	}
}

func PageCreate(writer http.ResponseWriter, request *http.Request) {
	if AdminUser == "" {
		var adminData AdminData
		err := json.NewDecoder(request.Body).Decode(&adminData)
		if err != nil {
			fmt.Fprintf(writer, "Failed! Invalid request.")
			return
		}
		adminErr := RegisterAdmin(adminData.Username, adminData.Password)
		if adminErr != nil {
			fmt.Fprintf(writer, "Failed! Could not add to database.")
			return
		}
		InitAuth()
		if AdminUser != "" && AdminPassword != "" {
			fmt.Fprintf(writer, "ok")
			return
		} else {
			fmt.Fprintf(writer, "Failed! Could not fetch new data.")
			return
		}
	} else {
		fmt.Fprintf(writer, "Failed! Admin account already created.")
		return
	}
}

func PageDashboard(writer http.ResponseWriter, request *http.Request) {
	if IsAuthed(request) {
		fmt.Fprintf(writer, "You are authed")
	} else {
		fmt.Fprintf(writer, "You are not authed")
	}
}

func PageRules() {

}

type AdminData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
